use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;

pub const MAX_RESOLVED_ADDRESSES: usize = 32;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum EgressPolicy {
    #[default]
    PublicOnly,
    /// Explicit process-level test/legacy escape hatch. It is deliberately not
    /// a Registry field and must never be inferred from an untrusted document.
    AllowNonPublic,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EgressError {
    #[error("non-public egress blocked: {ip} ({class})")]
    NonPublic { ip: IpAddr, class: &'static str },
    #[error("DNS resolution returned no addresses")]
    EmptyResolution,
    #[error(
        "DNS resolution returned too many addresses: limit={MAX_RESOLVED_ADDRESSES}, actual={0}"
    )]
    TooManyAddresses(usize),
    #[error("DNS resolution timed out after {0:?}")]
    ResolutionTimeout(Duration),
    #[error("DNS resolution failed: {0}")]
    Resolution(String),
}

pub trait Resolve: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

impl<F> Resolve for F
where
    F: Fn(&str, u16) -> io::Result<Vec<SocketAddr>> + Send + Sync,
{
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self(host, port)
    }
}

#[derive(Debug)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        (host, port).to_socket_addrs().map(Iterator::collect)
    }
}

fn in_v4(ip: Ipv4Addr, base: [u8; 4], prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
    u32::from(ip) & mask == u32::from(Ipv4Addr::from(base)) & mask
}

fn in_v6(ip: Ipv6Addr, base: Ipv6Addr, prefix: u8) -> bool {
    let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
    u128::from(ip) & mask == u128::from(base) & mask
}

fn ipv4_class(ip: Ipv4Addr) -> &'static str {
    const BLOCKED: &[([u8; 4], u8, &str)] = &[
        ([0, 0, 0, 0], 8, "unspecified_or_this_network"),
        ([10, 0, 0, 0], 8, "private"),
        ([100, 64, 0, 0], 10, "shared"),
        ([127, 0, 0, 0], 8, "loopback"),
        ([169, 254, 0, 0], 16, "link_local"),
        ([172, 16, 0, 0], 12, "private"),
        ([192, 0, 0, 0], 24, "ietf_protocol"),
        ([192, 0, 2, 0], 24, "documentation"),
        ([192, 88, 99, 0], 24, "transition"),
        ([192, 168, 0, 0], 16, "private"),
        ([198, 18, 0, 0], 15, "benchmarking"),
        ([198, 51, 100, 0], 24, "documentation"),
        ([203, 0, 113, 0], 24, "documentation"),
        ([224, 0, 0, 0], 4, "multicast"),
        ([240, 0, 0, 0], 4, "reserved"),
    ];
    BLOCKED
        .iter()
        .find_map(|(base, prefix, class)| in_v4(ip, *base, *prefix).then_some(*class))
        .unwrap_or("public")
}

fn ipv6_class(ip: Ipv6Addr) -> &'static str {
    if ip.is_unspecified() {
        return "unspecified";
    }
    if ip.is_loopback() {
        return "loopback";
    }
    // Fail closed on all translated/transition forms instead of assuming that
    // an embedded public IPv4 address makes the outer destination safe.
    if ip.to_ipv4_mapped().is_some() {
        return "ipv4_mapped";
    }
    if in_v6(ip, "64:ff9b::".parse().expect("constant"), 96)
        || in_v6(ip, "64:ff9b:1::".parse().expect("constant"), 48)
    {
        return "nat64";
    }
    if in_v6(ip, "100::".parse().expect("constant"), 64) {
        return "discard";
    }
    if in_v6(ip, "2001:2::".parse().expect("constant"), 48) {
        return "benchmarking";
    }
    if in_v6(ip, "2001::".parse().expect("constant"), 23) {
        return "transition_or_ietf";
    }
    if in_v6(ip, "2001:db8::".parse().expect("constant"), 32)
        || in_v6(ip, "3fff::".parse().expect("constant"), 20)
    {
        return "documentation";
    }
    if in_v6(ip, "2002::".parse().expect("constant"), 16) {
        return "transition";
    }
    if in_v6(ip, "fc00::".parse().expect("constant"), 7) {
        return "unique_local";
    }
    if in_v6(ip, "fe80::".parse().expect("constant"), 10) {
        return "link_local";
    }
    if in_v6(ip, "ff00::".parse().expect("constant"), 8) {
        return "multicast";
    }
    if !in_v6(ip, "2000::".parse().expect("constant"), 3) {
        return "non_global_unicast";
    }
    "public"
}

pub fn address_class(ip: IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(ip) => ipv4_class(ip),
        IpAddr::V6(ip) => ipv6_class(ip),
    }
}

pub fn validate_ip(ip: IpAddr, policy: EgressPolicy) -> Result<(), EgressError> {
    let class = address_class(ip);
    if policy == EgressPolicy::PublicOnly && class != "public" {
        return Err(EgressError::NonPublic { ip, class });
    }
    Ok(())
}

pub(crate) fn validate_addresses(
    addresses: Vec<SocketAddr>,
    port: u16,
    policy: EgressPolicy,
) -> Result<Vec<SocketAddr>, EgressError> {
    if addresses.is_empty() {
        return Err(EgressError::EmptyResolution);
    }
    if addresses.len() > MAX_RESOLVED_ADDRESSES {
        return Err(EgressError::TooManyAddresses(addresses.len()));
    }
    let mut validated = Vec::with_capacity(addresses.len());
    for address in addresses {
        validate_ip(address.ip(), policy)?;
        let pinned = SocketAddr::new(address.ip(), port);
        if !validated.contains(&pinned) {
            validated.push(pinned);
        }
    }
    Ok(validated)
}

/// Resolve once in a bounded worker and validate the complete answer. The
/// caller receives the exact addresses that the HTTP agent will later dial.
/// A timed-out resolver worker has no HTTP agent and cannot initiate a fetch.
pub(crate) fn resolve_validated(
    resolver: Arc<dyn Resolve>,
    host: &str,
    port: u16,
    policy: EgressPolicy,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, EgressError> {
    let host = host.to_owned();
    let (sender, receiver) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("asfa-dns-resolve".into())
        .spawn(move || {
            let _ = sender.send(resolver.resolve(&host, port));
        })
        .map_err(|error| EgressError::Resolution(error.to_string()))?;
    let addresses = match receiver.recv_timeout(timeout) {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(error)) => return Err(EgressError::Resolution(error.to_string())),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            return Err(EgressError::ResolutionTimeout(timeout));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            return Err(EgressError::Resolution(
                "resolver worker disconnected".into(),
            ));
        }
    };
    validate_addresses(addresses, port, policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::time::Instant;

    #[derive(Deserialize)]
    struct Case {
        ip: IpAddr,
        public: bool,
        class: String,
    }

    #[test]
    fn preregistered_address_classes_match_independent_known_answers() {
        #[derive(Deserialize)]
        struct Fixture {
            cases: Vec<Case>,
        }
        let fixture: Fixture =
            serde_json::from_str(include_str!("../../fixtures/egress-address-cases.json")).unwrap();
        assert!(fixture.cases.len() >= 40);
        for case in fixture.cases {
            assert_eq!(address_class(case.ip), case.class, "ip={}", case.ip);
            assert_eq!(
                validate_ip(case.ip, EgressPolicy::PublicOnly).is_ok(),
                case.public,
                "ip={}",
                case.ip
            );
        }
    }

    #[test]
    fn mixed_answers_and_answer_capacity_fail_closed() {
        let mixed = vec![
            "93.184.216.34:80".parse().unwrap(),
            "127.0.0.1:80".parse().unwrap(),
        ];
        assert!(matches!(
            validate_addresses(mixed, 80, EgressPolicy::PublicOnly),
            Err(EgressError::NonPublic {
                class: "loopback",
                ..
            })
        ));
        let excessive = (0..=MAX_RESOLVED_ADDRESSES)
            .map(|index| SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), index as u16))
            .collect();
        assert_eq!(
            validate_addresses(excessive, 80, EgressPolicy::PublicOnly),
            Err(EgressError::TooManyAddresses(33))
        );
        assert_eq!(
            validate_addresses(vec![], 80, EgressPolicy::PublicOnly),
            Err(EgressError::EmptyResolution)
        );
    }

    #[test]
    fn resolution_wait_is_bounded_even_when_the_worker_is_slow() {
        let resolver: Arc<dyn Resolve> = Arc::new(|_host: &str, port: u16| {
            std::thread::sleep(Duration::from_millis(250));
            Ok(vec![SocketAddr::new("8.8.8.8".parse().unwrap(), port)])
        });
        let started = Instant::now();
        let error = resolve_validated(
            resolver,
            "slow.test",
            80,
            EgressPolicy::PublicOnly,
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(
            error,
            EgressError::ResolutionTimeout(Duration::from_millis(20))
        );
        assert!(started.elapsed() < Duration::from_millis(150));
    }
}
