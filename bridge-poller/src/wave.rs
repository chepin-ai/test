//! Deterministic, capacity-bounded QF-OS wave planning over verified directives.
//! This module produces a plan only; it never executes actions or consumes jobs.

use crate::ledger::DirectiveLedger;
use crate::model::Directive;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub const WAVE_PLAN_SCHEMA_VERSION: &str = "qfos-wave-plan/v1";
pub const WAVE_PLAN_DIGEST_DOMAIN: &str = "ASFA-OS-XI/QFOS-WAVE-PLAN/V1\n";
pub const LEDGER_DIGEST_DOMAIN: &str = "ASFA-OS-XI/DIRECTIVE-LEDGER-SNAPSHOT/V1\n";
pub const DEFAULT_WAVE_MAX_JOBS: usize = 64;
pub const DEFAULT_WAVE_MAX_PER_SOURCE: usize = 16;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WaveJob {
    pub session: String,
    pub id: String,
    pub action: String,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_epoch: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WaveSourceStats {
    pub session: String,
    pub offered: usize,
    pub admitted: usize,
    pub deferred_wave_quota: usize,
    pub deferred_source_quota: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WavePlan {
    pub schema_version: String,
    pub mode: String,
    pub network_name: String,
    pub policy_hash: String,
    pub ledger_hash: String,
    pub target: String,
    pub generated_at_epoch: u64,
    pub max_jobs: usize,
    pub max_per_source: usize,
    pub jobs: Vec<WaveJob>,
    pub deferred: usize,
    pub sources: Vec<WaveSourceStats>,
    pub plan_hash: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WaveError {
    #[error("wave target must not be empty")]
    EmptyTarget,
    #[error("wave quotas must be greater than zero")]
    ZeroQuota,
    #[error("wave planning requires a ledger bound to network and registry policy")]
    UnboundLedger,
}

fn digest(domain: &str, value: &Value) -> String {
    let mut encoded = domain.as_bytes().to_vec();
    encoded.extend(serde_json::to_vec(value).expect("wave projection always serializes"));
    format!("{:x}", Sha256::digest(&encoded))
}

pub fn ledger_digest(ledger: &DirectiveLedger) -> String {
    let snapshot = serde_json::to_value(ledger.snapshot()).expect("ledger snapshot serializes");
    digest(LEDGER_DIGEST_DOMAIN, &snapshot)
}

fn job(session: &str, directive: &Directive) -> WaveJob {
    WaveJob {
        session: session.into(),
        id: directive.id.clone(),
        action: directive.action.clone(),
        payload: directive.payload.clone(),
        expires_epoch: directive.expires_epoch,
    }
}

/// Select jobs by source round-robin. A source cannot consume more than
/// `max_per_source` slots even when other sources are idle. Deferred accounting
/// gives source-quota precedence when both quotas could explain rejection.
pub fn plan_wave(
    ledger: &DirectiveLedger,
    target: &str,
    now_epoch: u64,
    max_jobs: usize,
    max_per_source: usize,
) -> Result<WavePlan, WaveError> {
    if target.trim().is_empty() {
        return Err(WaveError::EmptyTarget);
    }
    if max_jobs == 0 || max_per_source == 0 {
        return Err(WaveError::ZeroQuota);
    }
    let (Some(network_name), Some(policy_hash)) = (ledger.network_name(), ledger.policy_hash())
    else {
        return Err(WaveError::UnboundLedger);
    };

    let entries = ledger.pending_entries_for_at(target, now_epoch);
    let mut groups: BTreeMap<&str, Vec<&Directive>> = BTreeMap::new();
    for (session, directive) in entries {
        groups.entry(session).or_default().push(directive);
    }

    let mut jobs = Vec::new();
    let mut selected = BTreeSet::new();
    let mut admitted: BTreeMap<&str, usize> = BTreeMap::new();
    let mut offsets: BTreeMap<&str, usize> = BTreeMap::new();
    while jobs.len() < max_jobs {
        let mut progressed = false;
        for (session, directives) in &groups {
            if jobs.len() >= max_jobs {
                break;
            }
            let offset = offsets.get(session).copied().unwrap_or(0);
            if offset >= directives.len()
                || admitted.get(session).copied().unwrap_or(0) >= max_per_source
            {
                continue;
            }
            let directive = directives[offset];
            offsets.insert(session, offset + 1);
            admitted.insert(session, admitted.get(session).copied().unwrap_or(0) + 1);
            selected.insert(((*session).to_owned(), directive.id.clone()));
            jobs.push(job(session, directive));
            progressed = true;
        }
        if !progressed {
            break;
        }
    }

    let mut sources = Vec::new();
    let mut deferred = 0;
    for (session, directives) in groups {
        let offered = directives.len();
        let admitted_count = admitted.get(session).copied().unwrap_or(0);
        let mut deferred_wave_quota = 0;
        let mut deferred_source_quota = 0;
        for directive in directives {
            if selected.contains(&(session.to_owned(), directive.id.clone())) {
                continue;
            }
            if admitted_count >= max_per_source {
                deferred_source_quota += 1;
            } else {
                deferred_wave_quota += 1;
            }
        }
        deferred += deferred_wave_quota + deferred_source_quota;
        sources.push(WaveSourceStats {
            session: session.into(),
            offered,
            admitted: admitted_count,
            deferred_wave_quota,
            deferred_source_quota,
        });
    }

    let mut plan = WavePlan {
        schema_version: WAVE_PLAN_SCHEMA_VERSION.into(),
        mode: "plan-only-no-execution".into(),
        network_name: network_name.into(),
        policy_hash: policy_hash.into(),
        ledger_hash: ledger_digest(ledger),
        target: target.into(),
        generated_at_epoch: now_epoch,
        max_jobs,
        max_per_source,
        jobs,
        deferred,
        sources,
        plan_hash: String::new(),
    };
    let projection = json!({
        "schema_version": &plan.schema_version,
        "mode": &plan.mode,
        "network_name": &plan.network_name,
        "policy_hash": &plan.policy_hash,
        "ledger_hash": &plan.ledger_hash,
        "target": &plan.target,
        "generated_at_epoch": plan.generated_at_epoch,
        "max_jobs": plan.max_jobs,
        "max_per_source": plan.max_per_source,
        "jobs": &plan.jobs,
        "deferred": plan.deferred,
        "sources": &plan.sources,
    });
    plan.plan_hash = digest(WAVE_PLAN_DIGEST_DOMAIN, &projection);
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Registry;
    use serde_json::json;

    fn directive(session: &str, id: &str) -> Directive {
        Directive {
            id: id.into(),
            from: session.into(),
            to: "qfos".into(),
            action: "engine.ping".into(),
            payload: json!({"id": id}),
            expires_epoch: None,
        }
    }

    fn ledger() -> DirectiveLedger {
        let registry = Registry {
            schema_version: "test".into(),
            network_name: "alpha".into(),
            trust_model: "unsigned-hash-chain".into(),
            sessions: BTreeMap::new(),
        };
        let mut ledger = DirectiveLedger::for_registry(&registry);
        for id in ["a1", "a2", "a3"] {
            ledger.ingest("a", directive("a", id), 100);
        }
        for id in ["b1", "b2"] {
            ledger.ingest("b", directive("b", id), 100);
        }
        ledger
    }

    #[test]
    fn wave_is_fair_bounded_deterministic_and_non_mutating() {
        let ledger = ledger();
        let before = serde_json::to_value(ledger.snapshot()).unwrap();
        let first = plan_wave(&ledger, "qfos", 100, 4, 1).unwrap();
        let second = plan_wave(&ledger, "qfos", 100, 4, 1).unwrap();
        assert_eq!(first, second);
        assert_eq!(
            first
                .jobs
                .iter()
                .map(|job| (job.session.as_str(), job.id.as_str()))
                .collect::<Vec<_>>(),
            vec![("a", "a1"), ("b", "b1")]
        );
        assert_eq!(first.deferred, 3);
        assert_eq!(first.sources[0].deferred_source_quota, 2);
        assert_eq!(first.sources[1].deferred_source_quota, 1);
        assert_eq!(serde_json::to_value(ledger.snapshot()).unwrap(), before);
        assert_eq!(first.plan_hash.len(), 64);
    }

    #[test]
    fn wave_requires_bound_ledger_and_nonzero_quotas() {
        let unbound = DirectiveLedger::new();
        assert_eq!(
            plan_wave(&unbound, "qfos", 100, 1, 1),
            Err(WaveError::UnboundLedger)
        );
        assert_eq!(
            plan_wave(&ledger(), "qfos", 100, 0, 1),
            Err(WaveError::ZeroQuota)
        );
    }
}
