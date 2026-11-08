use crate::chain::{verified_directives, verify_chain};
use crate::model::{BridgeReport, Outbox, PollRecord, PollStatus, Registry, Session, TrustMode};
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
        let records = registry
            .sessions
            .iter()
            .map(|(name, session)| {
                if registry.trust_model != SUPPORTED_TRUST_MODEL {
                    Self::record(
                        name,
                        session,
                        now_epoch,
                        PollStatus::InvalidTrust {
                            message: format!(
                                "unsupported registry trust_model: {}",
                                registry.trust_model
                            ),
                        },
                    )
                } else {
                    self.poll_session(name, session, now_epoch)
                }
            })
            .collect();
        BridgeReport::new(registry.network_name.clone(), now_epoch, records)
    }

    pub fn poll_session(&self, name: &str, session: &Session, now_epoch: u64) -> PollRecord {
        if session.trust != TrustMode::UnsignedHashChain {
            return Self::record(
                name,
                session,
                now_epoch,
                PollStatus::UnsupportedTrust {
                    mode: session.trust,
                },
            );
        }
        let status = match self.fetch(&session.url) {
            Err(FetchError::HttpStatus(code)) => PollStatus::HttpStatus { code },
            Err(FetchError::Transport(message)) => PollStatus::Transport { message },
            Err(FetchError::TooLarge) => PollStatus::Transport {
                message: format!("document exceeds {MAX_DOCUMENT_BYTES} bytes"),
            },
            Err(FetchError::InvalidUtf8) => PollStatus::InvalidJson {
                message: "document is not valid UTF-8".into(),
            },
            Ok(body) => Self::verify_document(name, session.trust, &body),
        };
        Self::record(name, session, now_epoch, status)
    }

    fn record(name: &str, session: &Session, now_epoch: u64, status: PollStatus) -> PollRecord {
        PollRecord {
            session: name.into(),
            url: session.url.clone(),
            fetched_at_epoch: now_epoch,
            status,
        }
    }

    fn verify_document(name: &str, expected_trust: TrustMode, body: &str) -> PollStatus {
        let value: Value = match serde_json::from_str(body) {
            Ok(value) => value,
            Err(error) => {
                return PollStatus::InvalidJson {
                    message: error.to_string(),
                }
            }
        };
        let outbox: Outbox = match serde_json::from_value(value) {
            Ok(outbox) => outbox,
            Err(error) => {
                return PollStatus::InvalidSchema {
                    message: error.to_string(),
                }
            }
        };
        if outbox.session != name {
            return PollStatus::InvalidSchema {
                message: format!(
                    "session mismatch: registry={name}, document={}",
                    outbox.session
                ),
            };
        }
        if outbox.trust != TrustMode::UnsignedHashChain {
            return PollStatus::UnsupportedTrust { mode: outbox.trust };
        }
        if outbox.trust != expected_trust {
            return PollStatus::InvalidTrust {
                message: format!(
                    "trust mismatch: registry={expected_trust:?}, document={:?}",
                    outbox.trust
                ),
            };
        }
        match verify_chain(&outbox.hash_chain) {
            Ok(verified_blocks) => match verified_directives(&outbox) {
                Ok(directives) => PollStatus::Verified {
                    verified_blocks,
                    verified_directives: directives.len(),
                    untrusted_directives: outbox.directives.len(),
                },
                Err(error) => PollStatus::InvalidTrust {
                    message: error.to_string(),
                },
            },
            Err(error) => PollStatus::InvalidTrust {
                message: error.to_string(),
            },
        }
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
