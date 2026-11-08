use crate::chain::{verified_directives, verify_chain};
use crate::model::{
    BridgeReport, Outbox, PollRecord, PollStatus, Registry, Session, SessionPoll, TrustMode,
};
use serde_json::Value;
use std::fs;
use std::io::Read;
use std::time::Duration;
use thiserror::Error;

pub const MAX_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
pub const SUPPORTED_TRUST_MODEL: &str = "unsigned-hash-chain";

#[derive(Debug, Error)]
enum FetchError {
    #[error("http status {0}")]
    HttpStatus(u16),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("document exceeds {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge,
    #[error("document is not valid UTF-8")]
    InvalidUtf8,
}

pub struct Poller {
    agent: ureq::Agent,
}

impl Default for Poller {
    fn default() -> Self {
        Self::new()
    }
}

impl Poller {
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(15))
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            agent: ureq::AgentBuilder::new().timeout(timeout).build(),
        }
    }

    pub fn poll_registry(&self, registry: &Registry, now_epoch: u64) -> BridgeReport {
        let records = self
            .poll_registry_detailed(registry, now_epoch)
            .into_iter()
            .map(|result| result.record)
            .collect();
        BridgeReport::new(registry.network_name.clone(), now_epoch, records)
    }

    pub fn poll_registry_detailed(&self, registry: &Registry, now_epoch: u64) -> Vec<SessionPoll> {
        registry
            .sessions
            .iter()
            .map(|(name, session)| {
                if registry.trust_model != SUPPORTED_TRUST_MODEL {
                    SessionPoll {
                        record: Self::record(
                            name,
                            session,
                            now_epoch,
                            PollStatus::InvalidTrust {
                                message: format!(
                                    "unsupported registry trust_model: {}",
                                    registry.trust_model
                                ),
                            },
                        ),
                        outbox: None,
                    }
                } else {
                    self.poll_session_detailed(name, session, now_epoch)
                }
            })
            .collect()
    }

    pub fn poll_session(&self, name: &str, session: &Session, now_epoch: u64) -> PollRecord {
        self.poll_session_detailed(name, session, now_epoch).record
    }

    pub fn poll_session_detailed(
        &self,
        name: &str,
        session: &Session,
        now_epoch: u64,
    ) -> SessionPoll {
        if session.trust != TrustMode::UnsignedHashChain {
            return SessionPoll {
                record: Self::record(
                    name,
                    session,
                    now_epoch,
                    PollStatus::UnsupportedTrust {
                        mode: session.trust,
                    },
                ),
                outbox: None,
            };
        }
        let (status, outbox) = match self.fetch(&session.url) {
            Err(FetchError::HttpStatus(code)) => (PollStatus::HttpStatus { code }, None),
            Err(FetchError::Transport(message)) => (PollStatus::Transport { message }, None),
            Err(FetchError::TooLarge) => (
                PollStatus::Transport {
                    message: format!("document exceeds {MAX_DOCUMENT_BYTES} bytes"),
                },
                None,
            ),
            Err(FetchError::InvalidUtf8) => (
                PollStatus::InvalidJson {
                    message: "document is not valid UTF-8".into(),
                },
                None,
            ),
            Ok(body) => match Self::verify_document(name, session.trust, &body) {
                Ok((status, outbox)) => (status, Some(outbox)),
                Err(status) => (status, None),
            },
        };
        SessionPoll {
            record: Self::record(name, session, now_epoch, status),
            outbox,
        }
    }

    fn record(name: &str, session: &Session, now_epoch: u64, status: PollStatus) -> PollRecord {
        PollRecord {
            session: name.into(),
            url: session.url.clone(),
            fetched_at_epoch: now_epoch,
            status,
        }
    }

    fn verify_document(
        name: &str,
        expected_trust: TrustMode,
        body: &str,
    ) -> Result<(PollStatus, Outbox), PollStatus> {
        let value: Value = serde_json::from_str(body).map_err(|error| PollStatus::InvalidJson {
            message: error.to_string(),
        })?;
        let outbox: Outbox =
            serde_json::from_value(value).map_err(|error| PollStatus::InvalidSchema {
                message: error.to_string(),
            })?;
        if outbox.session != name {
            return Err(PollStatus::InvalidSchema {
                message: format!(
                    "session mismatch: registry={name}, document={}",
                    outbox.session
                ),
            });
        }
        if outbox.trust != TrustMode::UnsignedHashChain {
            return Err(PollStatus::UnsupportedTrust { mode: outbox.trust });
        }
        if outbox.trust != expected_trust {
            return Err(PollStatus::InvalidTrust {
                message: format!(
                    "trust mismatch: registry={expected_trust:?}, document={:?}",
                    outbox.trust
                ),
            });
        }
        let verified_blocks =
            verify_chain(&outbox.hash_chain).map_err(|error| PollStatus::InvalidTrust {
                message: error.to_string(),
            })?;
        let directives =
            verified_directives(&outbox).map_err(|error| PollStatus::InvalidTrust {
                message: error.to_string(),
            })?;
        Ok((
            PollStatus::Verified {
                verified_blocks,
                verified_directives: directives.len(),
                untrusted_directives: outbox.directives.len(),
            },
            outbox,
        ))
    }

    fn fetch(&self, url: &str) -> Result<String, FetchError> {
        if let Some(path) = url.strip_prefix("file://") {
            let file =
                fs::File::open(path).map_err(|error| FetchError::Transport(error.to_string()))?;
            if file
                .metadata()
                .map_err(|error| FetchError::Transport(error.to_string()))?
                .len()
                > MAX_DOCUMENT_BYTES
            {
                return Err(FetchError::TooLarge);
            }
            let mut bytes = Vec::new();
            file.take(MAX_DOCUMENT_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| FetchError::Transport(error.to_string()))?;
            if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
                return Err(FetchError::TooLarge);
            }
            return String::from_utf8(bytes).map_err(|_| FetchError::InvalidUtf8);
        }
        if !(url.starts_with("https://") || url.starts_with("http://")) {
            return Err(FetchError::Transport("unsupported URL scheme".into()));
        }

        let response = self.agent.get(url).call().map_err(|error| match error {
            ureq::Error::Status(code, _) => FetchError::HttpStatus(code),
            ureq::Error::Transport(transport) => FetchError::Transport(transport.to_string()),
        })?;
        let mut bytes = Vec::new();
        response
            .into_reader()
            .take(MAX_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| FetchError::Transport(error.to_string()))?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            return Err(FetchError::TooLarge);
        }
        String::from_utf8(bytes).map_err(|_| FetchError::InvalidUtf8)
    }
}
