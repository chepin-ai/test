use crate::chain::{verified_directives, verify_chain};
use crate::egress::{
    resolve_validated, validate_addresses, EgressError, EgressPolicy, Resolve, SystemResolver,
};
use crate::model::{
    BridgeReport, Outbox, PollRecord, PollStatus, Registry, Session, SessionPoll, TrustMode,
};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;

pub const MAX_DOCUMENT_BYTES: u64 = 2 * 1024 * 1024;
pub const SUPPORTED_TRUST_MODEL: &str = "unsigned-hash-chain";

#[derive(Debug, Error)]
enum FetchError {
    #[error("http status {0}")]
    HttpStatus(u16),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("{0}")]
    Egress(#[from] EgressError),
    #[error("document exceeds {MAX_DOCUMENT_BYTES} bytes")]
    TooLarge,
    #[error("document is not valid UTF-8")]
    InvalidUtf8,
}

#[derive(Debug, Error)]
#[error("whole-poll deadline exceeded {phase}")]
pub struct PollDeadlineError {
    phase: String,
}

pub struct Poller {
    timeout: Duration,
    egress_policy: EgressPolicy,
    resolver: Arc<dyn Resolve>,
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
            timeout,
            egress_policy: EgressPolicy::PublicOnly,
            resolver: Arc::new(SystemResolver),
        }
    }

    /// Explicit process-level escape hatch for local tests and controlled
    /// legacy deployments. It is intentionally absent from Session JSON.
    pub fn with_egress_policy(policy: EgressPolicy) -> Self {
        Self {
            egress_policy: policy,
            ..Self::new()
        }
    }

    #[cfg(test)]
    fn with_resolver_for_test(
        timeout: Duration,
        egress_policy: EgressPolicy,
        resolver: Arc<dyn Resolve>,
    ) -> Self {
        Self {
            timeout,
            egress_policy,
            resolver,
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

    /// Compatibility helper with only per-request timeouts. Callers handling
    /// untrusted registries should use the whole-poll deadline variant below.
    pub fn poll_registry_detailed(&self, registry: &Registry, now_epoch: u64) -> Vec<SessionPoll> {
        registry
            .sessions
            .iter()
            .map(|(name, session)| {
                self.poll_registry_session(registry, name, session, now_epoch, self.timeout)
            })
            .collect()
    }

    /// Poll all sessions under one wall-clock deadline. Each request receives
    /// only the remaining time, and expiry between sessions aborts the batch.
    pub fn poll_registry_detailed_with_deadline(
        &self,
        registry: &Registry,
        now_epoch: u64,
        deadline: Instant,
    ) -> Result<Vec<SessionPoll>, PollDeadlineError> {
        let mut results = Vec::with_capacity(registry.sessions.len());
        for (name, session) in &registry.sessions {
            let remaining = Self::remaining(deadline, &format!("before session {name}"))?;
            results.push(self.poll_registry_session(registry, name, session, now_epoch, remaining));
            Self::ensure_deadline(deadline, &format!("after session {name}"))?;
        }
        Ok(results)
    }

    pub fn ensure_deadline(deadline: Instant, phase: &str) -> Result<(), PollDeadlineError> {
        Self::remaining(deadline, phase).map(|_| ())
    }

    fn remaining(deadline: Instant, phase: &str) -> Result<Duration, PollDeadlineError> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| PollDeadlineError {
                phase: phase.to_owned(),
            })
    }

    fn poll_registry_session(
        &self,
        registry: &Registry,
        name: &str,
        session: &Session,
        now_epoch: u64,
        request_timeout: Duration,
    ) -> SessionPoll {
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
            self.poll_session_detailed_within(name, session, now_epoch, request_timeout)
        }
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
        self.poll_session_detailed_within(name, session, now_epoch, self.timeout)
    }

    fn poll_session_detailed_within(
        &self,
        name: &str,
        session: &Session,
        now_epoch: u64,
        request_timeout: Duration,
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
        let (status, outbox) = match self.fetch(session, request_timeout) {
            Err(FetchError::HttpStatus(code)) => (PollStatus::HttpStatus { code }, None),
            Err(FetchError::Transport(message)) => (PollStatus::Transport { message }, None),
            Err(FetchError::Egress(error @ EgressError::NonPublic { .. })) => (
                PollStatus::BlockedEgress {
                    message: error.to_string(),
                },
                None,
            ),
            Err(FetchError::Egress(error)) => (
                PollStatus::Transport {
                    message: error.to_string(),
                },
                None,
            ),
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
            Ok(body) => match Self::verify_document(name, session, &body) {
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
        session: &Session,
        body: &str,
    ) -> Result<(PollStatus, Outbox), PollStatus> {
        let value =
            crate::strict_json::value_from_str(body).map_err(|error| PollStatus::InvalidJson {
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
        if outbox.url != session.canonical_url() {
            return Err(PollStatus::InvalidTrust {
                message: format!(
                    "canonical URL mismatch: expected={}, document={}",
                    session.canonical_url(),
                    outbox.url
                ),
            });
        }
        if outbox.trust != TrustMode::UnsignedHashChain {
            return Err(PollStatus::UnsupportedTrust { mode: outbox.trust });
        }
        if outbox.trust != session.trust {
            return Err(PollStatus::InvalidTrust {
                message: format!(
                    "trust mismatch: registry={:?}, document={:?}",
                    session.trust, outbox.trust
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

    fn fetch(&self, session: &Session, request_timeout: Duration) -> Result<String, FetchError> {
        let url = &session.url;
        let parsed = url::Url::parse(url)
            .map_err(|error| FetchError::Transport(format!("invalid URL: {error}")))?;
        if parsed.fragment().is_some() {
            return Err(FetchError::Transport(
                "URL fragments are not allowed in transport policy".into(),
            ));
        }
        match parsed.scheme() {
            "file" => {
                if !session.allow_file {
                    return Err(FetchError::Transport(
                        "file transport requires explicit allow_file=true".into(),
                    ));
                }
            }
            "http" | "https" => {
                if parsed.scheme() == "http" && !session.allow_insecure_http {
                    return Err(FetchError::Transport(
                        "insecure HTTP requires explicit allow_insecure_http=true".into(),
                    ));
                }
                if parsed.host_str().is_none() {
                    return Err(FetchError::Transport("URL host is required".into()));
                }
                if !parsed.username().is_empty() || parsed.password().is_some() {
                    return Err(FetchError::Transport("URL userinfo is not allowed".into()));
                }
            }
            _ => return Err(FetchError::Transport("unsupported URL scheme".into())),
        }

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

        let budget = self.timeout.min(request_timeout);
        let started = Instant::now();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| FetchError::Transport("URL port is required".into()))?;
        let addresses = match parsed.host() {
            Some(url::Host::Domain(host)) => resolve_validated(
                Arc::clone(&self.resolver),
                host,
                port,
                self.egress_policy,
                budget,
            )?,
            Some(url::Host::Ipv4(ip)) => validate_addresses(
                vec![SocketAddr::new(IpAddr::V4(ip), port)],
                port,
                self.egress_policy,
            )?,
            Some(url::Host::Ipv6(ip)) => validate_addresses(
                vec![SocketAddr::new(IpAddr::V6(ip), port)],
                port,
                self.egress_policy,
            )?,
            None => return Err(FetchError::Transport("URL host is required".into())),
        };
        let remaining = budget
            .checked_sub(started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                FetchError::Transport("request budget exhausted during DNS resolution".into())
            })?;
        // The resolver installed on this one-shot agent returns only the
        // validated addresses above. The URL itself is unchanged, preserving
        // the original Host header and TLS server name while preventing a
        // second DNS lookup from rebinding the actual connection.
        let agent = ureq::AgentBuilder::new()
            .timeout(remaining)
            .timeout_connect(remaining)
            .timeout_read(remaining)
            .timeout_write(remaining)
            .redirects(0)
            .try_proxy_from_env(false)
            .max_idle_connections(0)
            .resolver(move |_netloc: &str| Ok::<Vec<SocketAddr>, std::io::Error>(addresses.clone()))
            .build();
        let response = agent.get(url).call().map_err(|error| match error {
            ureq::Error::Status(code, _) => FetchError::HttpStatus(code),
            ureq::Error::Transport(transport) => FetchError::Transport(transport.to_string()),
        })?;
        if (300..400).contains(&response.status()) {
            return Err(FetchError::HttpStatus(response.status()));
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Outbox;
    use std::io::Write;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn session(url: String) -> Session {
        Session {
            url,
            canonical_url: None,
            role: None,
            trust: TrustMode::UnsignedHashChain,
            note: None,
            allow_insecure_http: true,
            allow_file: false,
        }
    }

    #[test]
    fn hostname_resolving_to_loopback_is_blocked_before_any_dial() {
        let resolutions = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&resolutions);
        let resolver: Arc<dyn Resolve> = Arc::new(move |host: &str, port: u16| {
            assert_eq!(host, "internal.test");
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(vec![SocketAddr::new("127.0.0.1".parse().unwrap(), port)])
        });
        let poller = Poller::with_resolver_for_test(
            Duration::from_secs(1),
            EgressPolicy::PublicOnly,
            resolver,
        );
        let record =
            poller.poll_session("node", &session("http://internal.test/outbox".into()), 100);
        assert!(matches!(
            record.status,
            PollStatus::BlockedEgress { message } if message.contains("loopback")
        ));
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn validated_resolution_is_the_only_resolution_and_the_actual_dial_target() {
        let listener_a = TcpListener::bind("127.0.0.1:0").unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").unwrap();
        let address_a = listener_a.local_addr().unwrap();
        let address_b = listener_b.local_addr().unwrap();
        let url = format!("http://pinned.test:{}/outbox", address_a.port());
        let body = serde_json::to_string(&Outbox::genesis("node", &url)).unwrap();
        let server_a = std::thread::spawn(move || {
            let (mut stream, _) = listener_a.accept().unwrap();
            let mut request = [0_u8; 2048];
            let count = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..count]).into_owned();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            request
        });
        let other_hits = Arc::new(AtomicUsize::new(0));
        let observed_hits = Arc::clone(&other_hits);
        std::thread::spawn(move || {
            if let Ok((_stream, _)) = listener_b.accept() {
                observed_hits.fetch_add(1, Ordering::SeqCst);
            }
        });

        let resolutions = Arc::new(AtomicUsize::new(0));
        let observed_resolutions = Arc::clone(&resolutions);
        let resolver: Arc<dyn Resolve> = Arc::new(move |host: &str, port: u16| {
            assert_eq!(host, "pinned.test");
            assert_eq!(port, address_a.port());
            let sequence = observed_resolutions.fetch_add(1, Ordering::SeqCst);
            let address = if sequence == 0 { address_a } else { address_b };
            Ok(vec![address])
        });
        let poller = Poller::with_resolver_for_test(
            Duration::from_secs(1),
            EgressPolicy::AllowNonPublic,
            resolver,
        );
        let record = poller.poll_session("node", &session(url), 100);
        assert!(record.status.is_verified(), "{:?}", record.status);
        assert_eq!(resolutions.load(Ordering::SeqCst), 1);
        assert_eq!(other_hits.load(Ordering::SeqCst), 0);
        let request = server_a.join().unwrap();
        assert!(
            request.contains(&format!("Host: pinned.test:{}\r\n", address_a.port())),
            "request did not preserve original authority: {request}"
        );
    }
}
