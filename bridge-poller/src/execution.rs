//! Bounded deterministic execution for qfos-exec-v1.
//!
//! Only pure built-in actions are admitted. There is no shell, network, dynamic
//! library, or external process execution. Outcomes and ledger consumption are
//! staged together and become visible only after the complete wave succeeds.

use crate::ledger::{DirectiveLedger, ExecutionCommitError};
use crate::model::{
    execution_input_digest, execution_output_digest, DeadLetterRecord, ExecutionReceipt,
};
use crate::wave::{verify_wave_plan, WaveError, WaveJob, WavePlan};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EXECUTION_REPORT_SCHEMA_VERSION: &str = "qfos-wave-execution/v1";
pub const EXECUTION_REPORT_DIGEST_DOMAIN: &str = "ASFA-OS-XI/QFOS-EXECUTION-REPORT/V1\n";
pub const EXECUTION_PROFILE: &str = "qfos-exec-v1";
pub const SUM_MAX_VALUES: usize = 1024;
pub const SHA256_MAX_UTF8_BYTES: usize = 1024 * 1024;
const DISPATCHER: &str = "dispatcher/qfos-exec-v1";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResult {
    pub session: String,
    pub id: String,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<ExecutionReceipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dead_letter: Option<DeadLetterRecord>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSummary {
    pub offered: usize,
    pub succeeded: usize,
    pub dead_lettered: usize,
    pub skipped_succeeded: usize,
    pub skipped_dead_lettered: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WaveExecutionReport {
    pub schema_version: String,
    pub profile: String,
    pub network_name: String,
    pub policy_hash: String,
    pub plan_hash: String,
    pub executed_at_epoch: u64,
    pub summary: ExecutionSummary,
    pub results: Vec<ExecutionResult>,
    pub execution_hash: String,
}

impl WaveExecutionReport {
    pub fn compute_hash(&self) -> String {
        let projection = json!({
            "schema_version": self.schema_version,
            "profile": self.profile,
            "network_name": self.network_name,
            "policy_hash": self.policy_hash,
            "plan_hash": self.plan_hash,
            "executed_at_epoch": self.executed_at_epoch,
            "summary": self.summary,
            "results": self.results,
        });
        let mut encoded = EXECUTION_REPORT_DIGEST_DOMAIN.as_bytes().to_vec();
        encoded.extend(serde_json::to_vec(&projection).expect("execution report serializes"));
        format!("{:x}", Sha256::digest(&encoded))
    }

    pub fn has_valid_hash(&self) -> bool {
        self.execution_hash == self.compute_hash()
            && self.results.iter().all(|result| {
                result
                    .receipt
                    .as_ref()
                    .is_none_or(ExecutionReceipt::has_valid_hash)
                    && result
                        .dead_letter
                        .as_ref()
                        .is_none_or(DeadLetterRecord::has_valid_hash)
            })
    }
}

#[derive(Debug, Error)]
pub enum ExecutionError {
    #[error("invalid wave plan: {0}")]
    InvalidPlan(#[from] WaveError),
    #[error("execution binding failed: {0}")]
    Binding(String),
    #[error("executed directive is already consumed without an outcome: {session}/{id}")]
    ConsumedWithoutOutcome { session: String, id: String },
    #[error("execution commit failed: {0}")]
    Commit(#[from] ExecutionCommitError),
}

#[derive(Debug)]
struct ExecutionFailure {
    code: &'static str,
    message: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SumInput {
    values: Vec<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Sha256Input {
    text: String,
}

fn invalid_payload(error: impl std::fmt::Display) -> ExecutionFailure {
    ExecutionFailure {
        code: "invalid_payload",
        message: error.to_string(),
    }
}

fn run_builtin(job: &WaveJob) -> (String, Result<Value, ExecutionFailure>) {
    match job.action.as_str() {
        "engine.sum" => {
            let engine = "builtin.sum/qfos-exec-v1".to_owned();
            let input: SumInput = match serde_json::from_value(job.payload.clone()) {
                Ok(input) => input,
                Err(error) => return (engine, Err(invalid_payload(error))),
            };
            if input.values.len() > SUM_MAX_VALUES {
                return (
                    engine,
                    Err(ExecutionFailure {
                        code: "input_limit",
                        message: format!(
                            "sum input exceeds {SUM_MAX_VALUES} values: actual={}",
                            input.values.len()
                        ),
                    }),
                );
            }
            let mut sum = 0_i64;
            for value in input.values.iter().copied() {
                let Some(next) = sum.checked_add(value) else {
                    return (
                        engine,
                        Err(ExecutionFailure {
                            code: "arithmetic_overflow",
                            message: "checked i64 sum overflowed".into(),
                        }),
                    );
                };
                sum = next;
            }
            (engine, Ok(json!({"count": input.values.len(), "sum": sum})))
        }
        "engine.sha256" => {
            let engine = "builtin.sha256/qfos-exec-v1".to_owned();
            let input: Sha256Input = match serde_json::from_value(job.payload.clone()) {
                Ok(input) => input,
                Err(error) => return (engine, Err(invalid_payload(error))),
            };
            let bytes = input.text.as_bytes();
            if bytes.len() > SHA256_MAX_UTF8_BYTES {
                return (
                    engine,
                    Err(ExecutionFailure {
                        code: "input_limit",
                        message: format!(
                            "SHA-256 input exceeds {SHA256_MAX_UTF8_BYTES} bytes: actual={}",
                            bytes.len()
                        ),
                    }),
                );
            }
            (
                engine,
                Ok(json!({
                    "bytes": bytes.len(),
                    "sha256": format!("{:x}", Sha256::digest(bytes)),
                })),
            )
        }
        _ => (
            DISPATCHER.into(),
            Err(ExecutionFailure {
                code: "unknown_action",
                message: format!("action is outside {EXECUTION_PROFILE}: {}", job.action),
            }),
        ),
    }
}

fn binding_error(message: impl Into<String>) -> ExecutionError {
    ExecutionError::Binding(message.into())
}

fn validate_existing_receipt(
    receipt: &ExecutionReceipt,
    job: &WaveJob,
    plan_hash: &str,
    input_hash: &str,
) -> Result<(), ExecutionError> {
    if receipt.session != job.session
        || receipt.id != job.id
        || receipt.action != job.action
        || receipt.plan_hash != plan_hash
        || receipt.input_hash != input_hash
        || !receipt.has_valid_hash()
    {
        return Err(binding_error(format!(
            "stored receipt does not match planned job {}/{}",
            job.session, job.id
        )));
    }
    Ok(())
}

fn validate_existing_dead_letter(
    dead_letter: &DeadLetterRecord,
    job: &WaveJob,
    plan_hash: &str,
    input_hash: &str,
) -> Result<(), ExecutionError> {
    if dead_letter.session != job.session
        || dead_letter.id != job.id
        || dead_letter.action != job.action
        || dead_letter.plan_hash != plan_hash
        || dead_letter.input_hash != input_hash
        || !dead_letter.has_valid_hash()
    {
        return Err(binding_error(format!(
            "stored dead letter does not match planned job {}/{}",
            job.session, job.id
        )));
    }
    Ok(())
}

/// Execute or resume a bound wave. All new outcomes are staged on a cloned
/// ledger; any binding or capacity error returns without changing the caller's
/// in-memory ledger. The caller must persist the returned ledger atomically.
pub fn execute_wave(
    ledger: &mut DirectiveLedger,
    plan: &WavePlan,
    now_epoch: u64,
) -> Result<WaveExecutionReport, ExecutionError> {
    verify_wave_plan(plan)?;
    let network_name = ledger
        .network_name()
        .ok_or_else(|| binding_error("execution requires a network-bound ledger"))?;
    let policy_hash = ledger
        .policy_hash()
        .ok_or_else(|| binding_error("execution requires a policy-bound ledger"))?;
    if plan.network_name != network_name || plan.policy_hash != policy_hash {
        return Err(binding_error(
            "plan network or policy does not match the execution ledger",
        ));
    }

    let mut staged = ledger.clone();
    let mut summary = ExecutionSummary {
        offered: plan.jobs.len(),
        ..ExecutionSummary::default()
    };
    let mut results = Vec::with_capacity(plan.jobs.len());

    for job in &plan.jobs {
        let input_hash = execution_input_digest(
            &job.session,
            &job.id,
            &job.action,
            &job.payload,
            job.expires_epoch,
        );
        if let Some(receipt) = staged.receipt(&job.session, &job.id) {
            validate_existing_receipt(receipt, job, &plan.plan_hash, &input_hash)?;
            summary.skipped_succeeded += 1;
            results.push(ExecutionResult {
                session: job.session.clone(),
                id: job.id.clone(),
                status: "skipped_succeeded".into(),
                receipt: Some(receipt.clone()),
                dead_letter: None,
            });
            continue;
        }
        if let Some(dead_letter) = staged.dead_letter(&job.session, &job.id) {
            validate_existing_dead_letter(dead_letter, job, &plan.plan_hash, &input_hash)?;
            summary.skipped_dead_lettered += 1;
            results.push(ExecutionResult {
                session: job.session.clone(),
                id: job.id.clone(),
                status: "skipped_dead_lettered".into(),
                receipt: None,
                dead_letter: Some(dead_letter.clone()),
            });
            continue;
        }
        if staged.is_consumed(&job.session, &job.id) {
            return Err(ExecutionError::ConsumedWithoutOutcome {
                session: job.session.clone(),
                id: job.id.clone(),
            });
        }
        let directive = staged
            .pending_entry(&job.session, &job.id)
            .ok_or_else(|| {
                binding_error(format!(
                    "planned job is neither pending nor completed: {}/{}",
                    job.session, job.id
                ))
            })?
            .clone();
        if directive.from != job.session
            || directive.action != job.action
            || directive.payload != job.payload
            || directive.expires_epoch != job.expires_epoch
            || (directive.to != plan.target && directive.to != "*")
        {
            return Err(binding_error(format!(
                "pending directive differs from planned job {}/{}",
                job.session, job.id
            )));
        }

        let (engine, outcome) = if job
            .expires_epoch
            .is_some_and(|expires| expires <= now_epoch)
        {
            (
                DISPATCHER.into(),
                Err(ExecutionFailure {
                    code: "expired",
                    message: format!("directive expired before execution at {now_epoch}"),
                }),
            )
        } else {
            run_builtin(job)
        };
        match outcome {
            Ok(output) => {
                let mut receipt = ExecutionReceipt {
                    session: job.session.clone(),
                    id: job.id.clone(),
                    action: job.action.clone(),
                    engine,
                    plan_hash: plan.plan_hash.clone(),
                    input_hash,
                    output_hash: execution_output_digest(&output),
                    output,
                    executed_at_epoch: now_epoch,
                    receipt_hash: String::new(),
                };
                receipt.refresh_hash();
                staged.record_receipt(receipt.clone())?;
                summary.succeeded += 1;
                results.push(ExecutionResult {
                    session: job.session.clone(),
                    id: job.id.clone(),
                    status: "succeeded".into(),
                    receipt: Some(receipt),
                    dead_letter: None,
                });
            }
            Err(failure) => {
                let mut dead_letter = DeadLetterRecord {
                    session: job.session.clone(),
                    id: job.id.clone(),
                    action: job.action.clone(),
                    engine,
                    plan_hash: plan.plan_hash.clone(),
                    input_hash,
                    code: failure.code.into(),
                    message: failure.message,
                    failed_at_epoch: now_epoch,
                    dead_letter_hash: String::new(),
                };
                dead_letter.refresh_hash();
                staged.record_dead_letter(dead_letter.clone())?;
                summary.dead_lettered += 1;
                results.push(ExecutionResult {
                    session: job.session.clone(),
                    id: job.id.clone(),
                    status: "dead_lettered".into(),
                    receipt: None,
                    dead_letter: Some(dead_letter),
                });
            }
        }
    }

    let mut report = WaveExecutionReport {
        schema_version: EXECUTION_REPORT_SCHEMA_VERSION.into(),
        profile: EXECUTION_PROFILE.into(),
        network_name: network_name.into(),
        policy_hash: policy_hash.into(),
        plan_hash: plan.plan_hash.clone(),
        executed_at_epoch: now_epoch,
        summary,
        results,
        execution_hash: String::new(),
    };
    report.execution_hash = report.compute_hash();
    *ledger = staged;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Directive, Registry};
    use crate::wave::plan_wave;
    use crate::{CapacityError, IngestOutcome, ResourceLimits};
    use std::collections::BTreeMap;

    fn registry() -> Registry {
        Registry {
            schema_version: "test".into(),
            network_name: "alpha".into(),
            trust_model: "unsigned-hash-chain".into(),
            sessions: BTreeMap::new(),
        }
    }

    fn directive(id: &str, action: &str, payload: Value, expires: Option<u64>) -> Directive {
        Directive {
            id: id.into(),
            from: "node".into(),
            to: "qfos".into(),
            action: action.into(),
            payload,
            expires_epoch: expires,
        }
    }

    fn admit(ledger: &mut DirectiveLedger, directive: Directive) {
        assert_eq!(ledger.ingest("node", directive, 1), IngestOutcome::Inserted);
    }

    #[test]
    fn builtins_dead_letters_and_replay_are_real_and_idempotent() {
        let mut ledger = DirectiveLedger::for_registry(&registry());
        admit(
            &mut ledger,
            directive("sum", "engine.sum", json!({"values": [1, 2, 39]}), None),
        );
        admit(
            &mut ledger,
            directive("sha", "engine.sha256", json!({"text": "abc"}), None),
        );
        admit(
            &mut ledger,
            directive("unknown", "engine.shell", json!({"command": "true"}), None),
        );
        admit(
            &mut ledger,
            directive(
                "invalid",
                "engine.sum",
                json!({"values": "not-an-array"}),
                None,
            ),
        );
        admit(
            &mut ledger,
            directive(
                "overflow",
                "engine.sum",
                json!({"values": [i64::MAX, 1]}),
                None,
            ),
        );
        admit(
            &mut ledger,
            directive(
                "too-many",
                "engine.sum",
                json!({"values": vec![0; SUM_MAX_VALUES + 1]}),
                None,
            ),
        );
        admit(
            &mut ledger,
            directive("expired", "engine.sum", json!({"values": [1]}), Some(99)),
        );
        let plan = plan_wave(&ledger, "qfos", 50, 16, 16).unwrap();
        assert_eq!(plan.jobs.len(), 7);

        let report = execute_wave(&mut ledger, &plan, 100).unwrap();
        assert!(report.has_valid_hash());
        assert_eq!(report.summary.offered, 7);
        assert_eq!(report.summary.succeeded, 2);
        assert_eq!(report.summary.dead_lettered, 5);
        assert_eq!(ledger.len(), 0);
        assert_eq!(ledger.consumed_len(), 7);
        assert_eq!(ledger.receipt_len(), 2);
        assert_eq!(ledger.dead_letter_len(), 5);

        let sum = ledger.receipt("node", "sum").unwrap();
        assert_eq!(sum.output, json!({"count": 3, "sum": 42}));
        assert!(sum.has_valid_hash());
        let sha = ledger.receipt("node", "sha").unwrap();
        assert_eq!(
            sha.output,
            json!({
                "bytes": 3,
                "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            })
        );
        let codes: BTreeMap<_, _> = ["unknown", "invalid", "overflow", "too-many", "expired"]
            .into_iter()
            .map(|id| {
                let dead = ledger.dead_letter("node", id).unwrap();
                assert!(dead.has_valid_hash());
                (id, dead.code.as_str())
            })
            .collect();
        assert_eq!(codes["unknown"], "unknown_action");
        assert_eq!(codes["invalid"], "invalid_payload");
        assert_eq!(codes["overflow"], "arithmetic_overflow");
        assert_eq!(codes["too-many"], "input_limit");
        assert_eq!(codes["expired"], "expired");

        let committed = ledger.snapshot();
        let replay = execute_wave(&mut ledger, &plan, 100).unwrap();
        assert_eq!(replay.summary.succeeded, 0);
        assert_eq!(replay.summary.dead_lettered, 0);
        assert_eq!(replay.summary.skipped_succeeded, 2);
        assert_eq!(replay.summary.skipped_dead_lettered, 5);
        assert_eq!(ledger.snapshot(), committed);

        let mut tampered = plan.clone();
        tampered.jobs[0].payload = json!({"values": [0]});
        assert!(matches!(
            execute_wave(&mut ledger, &tampered, 100),
            Err(ExecutionError::InvalidPlan(_))
        ));
        assert_eq!(ledger.snapshot(), committed);
    }

    #[test]
    fn capacity_failure_leaves_the_caller_ledger_byte_for_byte_equivalent() {
        let limits = ResourceLimits {
            max_consumed_tombstones: 1,
            ..ResourceLimits::default()
        };
        let mut ledger = DirectiveLedger::for_registry(&registry()).with_limits(limits);
        admit(
            &mut ledger,
            directive("a", "engine.sum", json!({"values": [1]}), None),
        );
        admit(
            &mut ledger,
            directive("b", "engine.sum", json!({"values": [2]}), None),
        );
        let plan = plan_wave(&ledger, "qfos", 50, 16, 16).unwrap();
        let before = ledger.snapshot();
        let error = execute_wave(&mut ledger, &plan, 50).unwrap_err();
        assert!(matches!(
            error,
            ExecutionError::Commit(ExecutionCommitError::Capacity(
                CapacityError::ConsumedTombstones { limit: 1 }
            ))
        ));
        assert_eq!(ledger.snapshot(), before);
        assert_eq!(ledger.receipt_len(), 0);
        assert_eq!(ledger.consumed_len(), 0);
    }

    #[test]
    fn consumed_without_an_outcome_fails_closed_without_mutation() {
        let mut ledger = DirectiveLedger::for_registry(&registry());
        admit(
            &mut ledger,
            directive("a", "engine.sum", json!({"values": [1]}), None),
        );
        let plan = plan_wave(&ledger, "qfos", 50, 16, 16).unwrap();
        ledger.consume("node", "a").unwrap();
        let before = ledger.snapshot();
        assert!(matches!(
            execute_wave(&mut ledger, &plan, 50),
            Err(ExecutionError::ConsumedWithoutOutcome { .. })
        ));
        assert_eq!(ledger.snapshot(), before);
    }
}
