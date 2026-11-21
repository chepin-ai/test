use crate::chain::ChainError;
use crate::model::{
    execution_input_digest, DeadLetterRecord, Directive, ExecutionReceipt, Outbox, Registry,
    GENESIS_HASH,
};
use crate::strict_json;
use crate::ticket::{TicketError, TicketLedger, TicketLedgerSnapshot, TicketTransactionKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

pub const LEDGER_SCHEMA_VERSION: &str = "asfa-directive-ledger/v4";
pub const TICKETED_LEDGER_SCHEMA_VERSION: &str = "asfa-directive-ledger/v5";
pub const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_PENDING_DIRECTIVES: usize = 4096;
pub const DEFAULT_MAX_CONSUMED_TOMBSTONES: usize = 16384;
pub const DEFAULT_MAX_DIRECTIVES_PER_OUTBOX: usize = 1024;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);
const MAX_TEMP_FILE_ATTEMPTS: u64 = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimits {
    pub max_pending_directives: usize,
    pub max_consumed_tombstones: usize,
    pub max_directives_per_outbox: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_pending_directives: DEFAULT_MAX_PENDING_DIRECTIVES,
            max_consumed_tombstones: DEFAULT_MAX_CONSUMED_TOMBSTONES,
            max_directives_per_outbox: DEFAULT_MAX_DIRECTIVES_PER_OUTBOX,
        }
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CapacityError {
    #[error("pending directive capacity exceeded: limit={limit}")]
    PendingDirectives { limit: usize },
    #[error("consumed tombstone capacity exceeded: limit={limit}")]
    ConsumedTombstones { limit: usize },
    #[error("outbox directive capacity exceeded: limit={limit}, actual={actual}")]
    DirectivesPerOutbox { limit: usize, actual: usize },
    #[error("ledger snapshot exceeds {limit} bytes: actual={actual}")]
    SnapshotBytes { limit: u64, actual: usize },
}

#[derive(Debug, Error)]
pub enum ExecutionCommitError {
    #[error("execution outcome is not pending: {session}/{id}")]
    NotPending { session: String, id: String },
    #[error("execution outcome conflicts with the pending directive: {session}/{id}")]
    Conflict { session: String, id: String },
    #[error("execution outcome exceeds ledger capacity: {0}")]
    Capacity(#[from] CapacityError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    Inserted,
    Duplicate,
    Consumed,
    Conflict,
    Expired,
    Invalid(String),
    OverCapacity,
}

type DirectiveKey = (String, String);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DirectiveEntry {
    pub session: String,
    pub directive: Directive,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConsumedKey {
    pub session: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChainCheckpoint {
    pub height: u64,
    pub latest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CheckpointEntry {
    pub session: String,
    pub height: u64,
    pub latest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LedgerSnapshot {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    pub directives: Vec<DirectiveEntry>,
    pub consumed: Vec<ConsumedKey>,
    pub checkpoints: Vec<CheckpointEntry>,
    #[serde(default)]
    pub receipts: Vec<ExecutionReceipt>,
    #[serde(default)]
    pub dead_letters: Vec<DeadLetterRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tickets: Option<TicketLedgerSnapshot>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RestoreError {
    #[error("unsupported ledger schema: {0}; refusing implicit migration")]
    UnsupportedSchema(String),
    #[error("invalid ledger entry: {0}")]
    InvalidEntry(String),
    #[error("duplicate directive in snapshot: {session}/{id}")]
    DuplicateDirective { session: String, id: String },
    #[error("duplicate consumed key in snapshot: {session}/{id}")]
    DuplicateConsumed { session: String, id: String },
    #[error("duplicate chain checkpoint in snapshot: {session}")]
    DuplicateCheckpoint { session: String },
    #[error("duplicate execution receipt in snapshot: {session}/{id}")]
    DuplicateReceipt { session: String, id: String },
    #[error("duplicate dead letter in snapshot: {session}/{id}")]
    DuplicateDeadLetter { session: String, id: String },
    #[error("consumed directive is also pending: {session}/{id}")]
    ConsumedPending { session: String, id: String },
    #[error("execution outcome conflicts in snapshot: {session}/{id}")]
    OutcomeConflict { session: String, id: String },
    #[error("ledger resource limit: {0}")]
    ResourceLimit(#[from] CapacityError),
    #[error("ticket ledger restore failed: {0}")]
    Ticket(#[from] TicketError),
}

/// Idempotent directive store with consumption tombstones and per-session chain
/// checkpoints. Persistence is explicit and supports a single writer; atomic
/// rename prevents torn files but does not provide multi-process compare-and-swap.
#[derive(Clone, Debug, Default)]
pub struct DirectiveLedger {
    network_name: Option<String>,
    policy_hash: Option<String>,
    directives: BTreeMap<DirectiveKey, Directive>,
    consumed: BTreeSet<DirectiveKey>,
    checkpoints: BTreeMap<String, ChainCheckpoint>,
    receipts: BTreeMap<DirectiveKey, ExecutionReceipt>,
    dead_letters: BTreeMap<DirectiveKey, DeadLetterRecord>,
    tickets: TicketLedger,
    limits: ResourceLimits,
}

impl DirectiveLedger {
    /// Construct an unbound in-memory ledger for isolated library use. Stateful
    /// CLI callers use `for_registry` or `load_for_registry` instead.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_network(network_name: impl Into<String>) -> Self {
        Self {
            network_name: Some(network_name.into()),
            ..Self::default()
        }
    }

    pub fn for_registry(registry: &Registry) -> Self {
        Self {
            network_name: Some(registry.network_name.clone()),
            policy_hash: Some(registry.policy_digest()),
            ..Self::default()
        }
    }

    pub fn network_name(&self) -> Option<&str> {
        self.network_name.as_deref()
    }

    pub fn policy_hash(&self) -> Option<&str> {
        self.policy_hash.as_deref()
    }

    pub fn tickets(&self) -> &TicketLedger {
        &self.tickets
    }

    pub fn tickets_mut(&mut self) -> &mut TicketLedger {
        &mut self.tickets
    }

    pub fn verify_ticket_execution_history(&self) -> Result<(), TicketError> {
        for transaction in self.tickets.transactions() {
            let TicketTransactionKind::Execute { plan_hash } = &transaction.kind else {
                continue;
            };
            for ticket_id in &transaction.inputs {
                let ticket = self.tickets.ticket(ticket_id).ok_or_else(|| {
                    TicketError::ExecutionHistory(format!("missing execute ticket: {ticket_id}"))
                })?;
                let job = ticket.job().ok_or_else(|| {
                    TicketError::ExecutionHistory(format!(
                        "control ticket in execute history: {ticket_id}"
                    ))
                })?;
                let key = (job.session.clone(), job.id.clone());
                let input_hash = execution_input_digest(
                    &job.session,
                    &job.id,
                    &job.action,
                    &job.payload,
                    job.expires_epoch,
                );
                let receipt_matches = self.receipts.get(&key).is_some_and(|receipt| {
                    receipt.action == job.action
                        && receipt.plan_hash == *plan_hash
                        && receipt.input_hash == input_hash
                        && receipt.executed_at_epoch == transaction.created_at_epoch
                });
                let dead_letter_matches = self.dead_letters.get(&key).is_some_and(|dead_letter| {
                    dead_letter.action == job.action
                        && dead_letter.plan_hash == *plan_hash
                        && dead_letter.input_hash == input_hash
                        && dead_letter.failed_at_epoch == transaction.created_at_epoch
                });
                if !self.consumed.contains(&key) || receipt_matches == dead_letter_matches {
                    return Err(TicketError::ExecutionHistory(format!(
                        "missing or conflicting outcome for {}/{}",
                        job.session, job.id
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn limits(&self) -> ResourceLimits {
        self.limits
    }

    pub fn with_limits(mut self, limits: ResourceLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn len(&self) -> usize {
        self.directives.len()
    }

    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    pub fn receipt_len(&self) -> usize {
        self.receipts.len()
    }

    pub fn dead_letter_len(&self) -> usize {
        self.dead_letters.len()
    }

    pub fn receipt(&self, session: &str, id: &str) -> Option<&ExecutionReceipt> {
        self.receipts.get(&(session.to_owned(), id.to_owned()))
    }

    pub fn dead_letter(&self, session: &str, id: &str) -> Option<&DeadLetterRecord> {
        self.dead_letters.get(&(session.to_owned(), id.to_owned()))
    }

    pub fn pending_entry(&self, session: &str, id: &str) -> Option<&Directive> {
        self.directives.get(&(session.to_owned(), id.to_owned()))
    }

    pub fn checkpoint(&self, session: &str) -> Option<&ChainCheckpoint> {
        self.checkpoints.get(session)
    }

    pub fn checkpoint_len(&self) -> usize {
        self.checkpoints.len()
    }

    fn validate(session: &str, directive: &Directive) -> Result<(), String> {
        if session.trim().is_empty() {
            return Err("session must not be empty".into());
        }
        if directive.id.trim().is_empty() {
            return Err("directive id must not be empty".into());
        }
        if directive.from != session {
            return Err(format!(
                "directive source mismatch: session={session}, from={}",
                directive.from
            ));
        }
        if directive.to.trim().is_empty() {
            return Err("directive target must not be empty".into());
        }
        if directive.action.trim().is_empty() {
            return Err("directive action must not be empty".into());
        }
        Ok(())
    }

    pub fn ingest(&mut self, session: &str, directive: Directive, now_epoch: u64) -> IngestOutcome {
        if let Err(reason) = Self::validate(session, &directive) {
            return IngestOutcome::Invalid(reason);
        }
        if directive
            .expires_epoch
            .is_some_and(|expires| expires <= now_epoch)
        {
            return IngestOutcome::Expired;
        }

        let key = (session.to_owned(), directive.id.clone());
        if self.consumed.contains(&key) {
            return IngestOutcome::Consumed;
        }
        if let Some(existing) = self.directives.get(&key) {
            return if existing == &directive {
                IngestOutcome::Duplicate
            } else {
                IngestOutcome::Conflict
            };
        }
        if self.directives.len() >= self.limits.max_pending_directives {
            return IngestOutcome::OverCapacity;
        }
        self.directives.insert(key, directive);
        IngestOutcome::Inserted
    }

    pub fn pending_entries_for_at(&self, target: &str, now_epoch: u64) -> Vec<(&str, &Directive)> {
        self.directives
            .iter()
            .filter(|(_, directive)| {
                (directive.to == target || directive.to == "*")
                    && directive
                        .expires_epoch
                        .is_none_or(|expires| expires > now_epoch)
            })
            .map(|((session, _), directive)| (session.as_str(), directive))
            .collect()
    }

    pub fn pending_for_at(&self, target: &str, now_epoch: u64) -> Vec<&Directive> {
        self.pending_entries_for_at(target, now_epoch)
            .into_iter()
            .map(|(_, directive)| directive)
            .collect()
    }

    /// Consuming removes the directive and leaves a tombstone so replaying the
    /// same session/ID cannot reinsert it during this ledger's lifetime. Capacity
    /// failure occurs before removal, so a failed consume never loses the job.
    pub fn consume(&mut self, session: &str, id: &str) -> Result<Option<Directive>, CapacityError> {
        let key = (session.to_owned(), id.to_owned());
        if !self.directives.contains_key(&key) {
            return Ok(None);
        }
        if self.consumed.len() >= self.limits.max_consumed_tombstones {
            return Err(CapacityError::ConsumedTombstones {
                limit: self.limits.max_consumed_tombstones,
            });
        }
        let directive = self.directives.remove(&key).expect("checked pending key");
        self.consumed.insert(key);
        Ok(Some(directive))
    }

    /// Commit a successful execution and its replay tombstone as one in-memory
    /// transaction. Capacity and binding checks happen before pending removal.
    pub fn record_receipt(
        &mut self,
        receipt: ExecutionReceipt,
    ) -> Result<bool, ExecutionCommitError> {
        let key = (receipt.session.clone(), receipt.id.clone());
        if self.receipts.get(&key) == Some(&receipt) {
            return Ok(false);
        }
        let Some(pending) = self.directives.get(&key) else {
            return Err(ExecutionCommitError::NotPending {
                session: receipt.session,
                id: receipt.id,
            });
        };
        if pending.action != receipt.action
            || !receipt.has_valid_hash()
            || self.dead_letters.contains_key(&key)
        {
            return Err(ExecutionCommitError::Conflict {
                session: receipt.session,
                id: receipt.id,
            });
        }
        if self.consumed.len() >= self.limits.max_consumed_tombstones {
            return Err(CapacityError::ConsumedTombstones {
                limit: self.limits.max_consumed_tombstones,
            }
            .into());
        }
        self.directives.remove(&key);
        self.consumed.insert(key.clone());
        self.receipts.insert(key, receipt);
        Ok(true)
    }

    /// Commit a failed execution as a dead letter plus a replay tombstone. The
    /// failed job cannot later be reinserted under the same structured key.
    pub fn record_dead_letter(
        &mut self,
        dead_letter: DeadLetterRecord,
    ) -> Result<bool, ExecutionCommitError> {
        let key = (dead_letter.session.clone(), dead_letter.id.clone());
        if self.dead_letters.get(&key) == Some(&dead_letter) {
            return Ok(false);
        }
        let Some(pending) = self.directives.get(&key) else {
            return Err(ExecutionCommitError::NotPending {
                session: dead_letter.session,
                id: dead_letter.id,
            });
        };
        if pending.action != dead_letter.action
            || !dead_letter.has_valid_hash()
            || self.receipts.contains_key(&key)
        {
            return Err(ExecutionCommitError::Conflict {
                session: dead_letter.session,
                id: dead_letter.id,
            });
        }
        if self.consumed.len() >= self.limits.max_consumed_tombstones {
            return Err(CapacityError::ConsumedTombstones {
                limit: self.limits.max_consumed_tombstones,
            }
            .into());
        }
        self.directives.remove(&key);
        self.consumed.insert(key.clone());
        self.dead_letters.insert(key, dead_letter);
        Ok(true)
    }

    pub fn is_consumed(&self, session: &str, id: &str) -> bool {
        self.consumed.contains(&(session.to_owned(), id.to_owned()))
    }

    /// Drop expired pending directives. Consumed tombstones are deliberately retained.
    pub fn prune_expired(&mut self, now_epoch: u64) -> usize {
        let before = self.directives.len();
        self.directives.retain(|_, directive| {
            directive
                .expires_epoch
                .is_none_or(|expires| expires > now_epoch)
        });
        before - self.directives.len()
    }

    /// Check a fully verified chain against the locally remembered head. This is
    /// an O(n) prefix comparison, not a compact Merkle consistency proof and not
    /// protection against replacement of the entire snapshot by an older file.
    pub(crate) fn checkpoint_for(&self, outbox: &Outbox) -> Result<ChainCheckpoint, ChainError> {
        let presented = &outbox.hash_chain;
        if let Some(stored) = self.checkpoints.get(&outbox.session) {
            if presented.height < stored.height {
                return Err(ChainError::Rollback {
                    session: outbox.session.clone(),
                    stored: stored.height,
                    presented: presented.height,
                });
            }
            if presented.height == stored.height {
                if presented.latest != stored.latest {
                    return Err(ChainError::Fork {
                        session: outbox.session.clone(),
                        height: stored.height,
                    });
                }
            } else if stored.height > 0 {
                let old_head = &presented.blocks[(stored.height - 1) as usize];
                if old_head.hash != stored.latest {
                    return Err(ChainError::Fork {
                        session: outbox.session.clone(),
                        height: stored.height,
                    });
                }
            }
        }
        Ok(ChainCheckpoint {
            height: presented.height,
            latest: presented.latest.clone(),
        })
    }

    pub(crate) fn commit_checkpoint(&mut self, session: &str, checkpoint: ChainCheckpoint) {
        self.checkpoints.insert(session.to_owned(), checkpoint);
    }

    pub fn snapshot(&self) -> LedgerSnapshot {
        let tickets = (!self.tickets.is_empty()).then(|| self.tickets.snapshot());
        LedgerSnapshot {
            schema_version: if tickets.is_some() {
                TICKETED_LEDGER_SCHEMA_VERSION.into()
            } else {
                LEDGER_SCHEMA_VERSION.into()
            },
            network_name: self.network_name.clone(),
            policy_hash: self.policy_hash.clone(),
            directives: self
                .directives
                .iter()
                .map(|((session, _), directive)| DirectiveEntry {
                    session: session.clone(),
                    directive: directive.clone(),
                })
                .collect(),
            consumed: self
                .consumed
                .iter()
                .map(|(session, id)| ConsumedKey {
                    session: session.clone(),
                    id: id.clone(),
                })
                .collect(),
            checkpoints: self
                .checkpoints
                .iter()
                .map(|(session, checkpoint)| CheckpointEntry {
                    session: session.clone(),
                    height: checkpoint.height,
                    latest: checkpoint.latest.clone(),
                })
                .collect(),
            receipts: self.receipts.values().cloned().collect(),
            dead_letters: self.dead_letters.values().cloned().collect(),
            tickets,
        }
    }

    pub fn from_snapshot(snapshot: LedgerSnapshot) -> Result<Self, RestoreError> {
        Self::from_snapshot_with_limits(snapshot, ResourceLimits::default())
    }

    pub fn from_snapshot_with_limits(
        snapshot: LedgerSnapshot,
        limits: ResourceLimits,
    ) -> Result<Self, RestoreError> {
        let ticket_ledger = match (snapshot.schema_version.as_str(), snapshot.tickets.clone()) {
            (LEDGER_SCHEMA_VERSION, None) => TicketLedger::default(),
            (TICKETED_LEDGER_SCHEMA_VERSION, Some(ticket_snapshot)) => {
                if ticket_snapshot.tickets.is_empty()
                    || Some(ticket_snapshot.network_name.as_str())
                        != snapshot.network_name.as_deref()
                    || Some(ticket_snapshot.policy_hash.as_str()) != snapshot.policy_hash.as_deref()
                {
                    return Err(RestoreError::InvalidEntry(
                        "v5 ticket ledger must be nonempty and match the outer registry binding"
                            .into(),
                    ));
                }
                TicketLedger::from_snapshot(ticket_snapshot)?
            }
            (LEDGER_SCHEMA_VERSION, Some(_)) => {
                return Err(RestoreError::InvalidEntry(
                    "v4 snapshot must not contain task tickets".into(),
                ));
            }
            (TICKETED_LEDGER_SCHEMA_VERSION, None) => {
                return Err(RestoreError::InvalidEntry(
                    "v5 snapshot requires a task-ticket ledger".into(),
                ));
            }
            _ => return Err(RestoreError::UnsupportedSchema(snapshot.schema_version)),
        };
        if snapshot
            .network_name
            .as_ref()
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(RestoreError::InvalidEntry(
                "network_name must not be empty when present".into(),
            ));
        }
        if snapshot
            .policy_hash
            .as_deref()
            .is_some_and(|hash| !valid_hash(hash))
        {
            return Err(RestoreError::InvalidEntry(
                "policy_hash must be a lowercase SHA-256 digest when present".into(),
            ));
        }
        if snapshot.directives.len() > limits.max_pending_directives {
            return Err(CapacityError::PendingDirectives {
                limit: limits.max_pending_directives,
            }
            .into());
        }
        if snapshot.consumed.len() > limits.max_consumed_tombstones {
            return Err(CapacityError::ConsumedTombstones {
                limit: limits.max_consumed_tombstones,
            }
            .into());
        }
        let mut ledger = Self {
            network_name: snapshot.network_name,
            policy_hash: snapshot.policy_hash,
            tickets: ticket_ledger,
            limits,
            ..Self::default()
        };
        for entry in snapshot.directives {
            Self::validate(&entry.session, &entry.directive).map_err(RestoreError::InvalidEntry)?;
            let key = (entry.session.clone(), entry.directive.id.clone());
            if ledger
                .directives
                .insert(key, entry.directive.clone())
                .is_some()
            {
                return Err(RestoreError::DuplicateDirective {
                    session: entry.session,
                    id: entry.directive.id,
                });
            }
        }
        for consumed in snapshot.consumed {
            if consumed.session.trim().is_empty() || consumed.id.trim().is_empty() {
                return Err(RestoreError::InvalidEntry(
                    "consumed session and id must not be empty".into(),
                ));
            }
            let key = (consumed.session.clone(), consumed.id.clone());
            if !ledger.consumed.insert(key) {
                return Err(RestoreError::DuplicateConsumed {
                    session: consumed.session,
                    id: consumed.id,
                });
            }
        }
        for receipt in snapshot.receipts {
            let key = (receipt.session.clone(), receipt.id.clone());
            if receipt.session.trim().is_empty()
                || receipt.id.trim().is_empty()
                || receipt.action.trim().is_empty()
                || receipt.engine.trim().is_empty()
                || !valid_hash(&receipt.plan_hash)
                || !valid_hash(&receipt.input_hash)
                || !valid_hash(&receipt.output_hash)
                || !valid_hash(&receipt.receipt_hash)
                || !receipt.has_valid_hash()
                || !ledger.consumed.contains(&key)
            {
                return Err(RestoreError::InvalidEntry(format!(
                    "invalid or unconsumed execution receipt: {}/{}",
                    receipt.session, receipt.id
                )));
            }
            if ledger.receipts.insert(key.clone(), receipt).is_some() {
                return Err(RestoreError::DuplicateReceipt {
                    session: key.0,
                    id: key.1,
                });
            }
        }
        for dead_letter in snapshot.dead_letters {
            let key = (dead_letter.session.clone(), dead_letter.id.clone());
            if dead_letter.session.trim().is_empty()
                || dead_letter.id.trim().is_empty()
                || dead_letter.action.trim().is_empty()
                || dead_letter.engine.trim().is_empty()
                || dead_letter.code.trim().is_empty()
                || !valid_hash(&dead_letter.plan_hash)
                || !valid_hash(&dead_letter.input_hash)
                || !valid_hash(&dead_letter.dead_letter_hash)
                || !dead_letter.has_valid_hash()
                || !ledger.consumed.contains(&key)
            {
                return Err(RestoreError::InvalidEntry(format!(
                    "invalid or unconsumed dead letter: {}/{}",
                    dead_letter.session, dead_letter.id
                )));
            }
            if ledger
                .dead_letters
                .insert(key.clone(), dead_letter)
                .is_some()
            {
                return Err(RestoreError::DuplicateDeadLetter {
                    session: key.0,
                    id: key.1,
                });
            }
        }
        for (session, id) in &ledger.consumed {
            let key = (session.clone(), id.clone());
            if ledger.directives.contains_key(&key) {
                return Err(RestoreError::ConsumedPending {
                    session: session.clone(),
                    id: id.clone(),
                });
            }
            if ledger.receipts.contains_key(&key) && ledger.dead_letters.contains_key(&key) {
                return Err(RestoreError::OutcomeConflict {
                    session: session.clone(),
                    id: id.clone(),
                });
            }
        }
        for entry in snapshot.checkpoints {
            if entry.session.trim().is_empty() {
                return Err(RestoreError::InvalidEntry(
                    "checkpoint session must not be empty".into(),
                ));
            }
            if !valid_hash(&entry.latest) || (entry.height == 0 && entry.latest != GENESIS_HASH) {
                return Err(RestoreError::InvalidEntry(format!(
                    "invalid checkpoint hash for session {}",
                    entry.session
                )));
            }
            let checkpoint = ChainCheckpoint {
                height: entry.height,
                latest: entry.latest,
            };
            if ledger
                .checkpoints
                .insert(entry.session.clone(), checkpoint)
                .is_some()
            {
                return Err(RestoreError::DuplicateCheckpoint {
                    session: entry.session,
                });
            }
        }
        ledger.verify_ticket_execution_history()?;
        Ok(ledger)
    }

    /// Atomically replace the snapshot within the destination filesystem. Temporary
    /// entries must be created exclusively by this process; pre-existing links or
    /// files are preserved and skipped with a bounded number of retries.
    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let rendered =
            serde_json::to_string_pretty(&self.snapshot()).map_err(io::Error::other)? + "\n";
        if rendered.len() as u64 > MAX_LEDGER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                CapacityError::SnapshotBytes {
                    limit: MAX_LEDGER_BYTES,
                    actual: rendered.len(),
                },
            ));
        }

        let mut allocated = None;
        for _ in 0..MAX_TEMP_FILE_ATTEMPTS {
            let serial = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
            let candidate = path.with_extension(format!("tmp-{}-{serial}", std::process::id()));
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&candidate)
            {
                Ok(mut file) => {
                    if let Err(error) = file.write_all(rendered.as_bytes()) {
                        drop(file);
                        return match fs::remove_file(&candidate) {
                            Ok(()) => Err(error),
                            Err(cleanup) => Err(io::Error::new(
                                error.kind(),
                                format!(
                                    "cannot write temporary state {}: {error}; cleanup also failed: {cleanup}",
                                    candidate.display()
                                ),
                            )),
                        };
                    }
                    drop(file);
                    allocated = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        let temporary = allocated.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "cannot allocate unique temporary state file for {} after {MAX_TEMP_FILE_ATTEMPTS} attempts",
                    path.display()
                ),
            )
        })?;
        if let Err(error) = fs::rename(&temporary, path) {
            return match fs::remove_file(&temporary) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(io::Error::new(
                    error.kind(),
                    format!(
                        "cannot replace state {}: {error}; temporary cleanup also failed: {cleanup}",
                        path.display()
                    ),
                )),
            };
        }
        Ok(())
    }

    fn read_snapshot(path: &Path) -> io::Result<LedgerSnapshot> {
        strict_json::from_path(path, MAX_LEDGER_BYTES)
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        Self::from_snapshot(Self::read_snapshot(path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn load_for_registry(path: &Path, registry: &Registry) -> io::Result<Self> {
        Self::load_for_registry_with_limits(path, registry, ResourceLimits::default())
    }

    pub fn load_for_registry_with_limits(
        path: &Path,
        registry: &Registry,
        limits: ResourceLimits,
    ) -> io::Result<Self> {
        let snapshot = Self::read_snapshot(path)?;
        if snapshot.schema_version != LEDGER_SCHEMA_VERSION
            && snapshot.schema_version != TICKETED_LEDGER_SCHEMA_VERSION
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported ledger schema: {}; refusing implicit migration",
                    snapshot.schema_version
                ),
            ));
        }
        if snapshot.network_name.as_deref() != Some(registry.network_name.as_str()) {
            let actual = snapshot.network_name.as_deref().unwrap_or("<unbound>");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ledger network mismatch: expected={}, actual={actual}; refusing implicit migration",
                    registry.network_name
                ),
            ));
        }
        let expected_policy = registry.policy_digest();
        if snapshot.policy_hash.as_deref() != Some(expected_policy.as_str()) {
            let actual = snapshot.policy_hash.as_deref().unwrap_or("<unbound>");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ledger policy mismatch: expected={expected_policy}, actual={actual}; refusing implicit migration"
                ),
            ));
        }
        Self::from_snapshot_with_limits(snapshot, limits)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    static SAVE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn directive(session: &str, id: &str, expires_epoch: Option<u64>) -> Directive {
        Directive {
            id: id.into(),
            from: session.into(),
            to: "cisvr".into(),
            action: "Ping".into(),
            payload: json!({}),
            expires_epoch,
        }
    }

    fn registry(network_name: &str) -> Registry {
        Registry {
            schema_version: "test".into(),
            network_name: network_name.into(),
            trust_model: "unsigned-hash-chain".into(),
            sessions: BTreeMap::new(),
        }
    }

    #[test]
    fn ingestion_is_idempotent_and_rejects_expired() {
        let mut ledger = DirectiveLedger::new();
        assert_eq!(
            ledger.ingest("a", directive("a", "one", Some(200)), 100),
            IngestOutcome::Inserted
        );
        assert_eq!(
            ledger.ingest("a", directive("a", "one", Some(200)), 100),
            IngestOutcome::Duplicate
        );
        assert_eq!(
            ledger.ingest("a", directive("a", "old", Some(99)), 100),
            IngestOutcome::Expired
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn consumption_leaves_a_replay_blocking_tombstone() {
        let mut ledger = DirectiveLedger::new();
        let item = directive("a", "once", None);
        assert_eq!(
            ledger.ingest("a", item.clone(), 100),
            IngestOutcome::Inserted
        );
        assert!(ledger.consume("a", "once").unwrap().is_some());
        assert!(ledger.consume("a", "once").unwrap().is_none());
        assert!(ledger.is_consumed("a", "once"));
        assert_eq!(ledger.ingest("a", item, 100), IngestOutcome::Consumed);
        assert!(ledger.is_empty());
    }

    #[test]
    fn changed_payload_with_same_id_is_a_conflict() {
        let mut ledger = DirectiveLedger::new();
        let original = directive("a", "same", None);
        let mut changed = original.clone();
        changed.action = "Different".into();
        assert_eq!(ledger.ingest("a", original, 100), IngestOutcome::Inserted);
        assert_eq!(ledger.ingest("a", changed, 100), IngestOutcome::Conflict);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn structured_keys_prevent_separator_collisions() {
        let mut ledger = DirectiveLedger::new();
        assert_eq!(
            ledger.ingest("a/b", directive("a/b", "c", None), 100),
            IngestOutcome::Inserted
        );
        assert_eq!(
            ledger.ingest("a", directive("a", "b/c", None), 100),
            IngestOutcome::Inserted
        );
        assert_eq!(ledger.len(), 2);
        assert!(ledger.consume("a/b", "c").unwrap().is_some());
        assert_eq!(ledger.pending_for_at("cisvr", 100).len(), 1);
    }

    #[test]
    fn pending_and_prune_recheck_expiration() {
        let mut ledger = DirectiveLedger::new();
        ledger.ingest("a", directive("a", "short", Some(150)), 100);
        ledger.ingest("a", directive("a", "long", Some(250)), 100);
        assert_eq!(ledger.pending_for_at("cisvr", 200).len(), 1);
        assert_eq!(ledger.prune_expired(200), 1);
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn ledger_rejects_forged_source_and_empty_fields() {
        let mut ledger = DirectiveLedger::new();
        assert!(matches!(
            ledger.ingest("a", directive("other", "forged", None), 100),
            IngestOutcome::Invalid(_)
        ));
        let mut empty_action = directive("a", "empty", None);
        empty_action.action = "  ".into();
        assert!(matches!(
            ledger.ingest("a", empty_action, 100),
            IngestOutcome::Invalid(_)
        ));
    }

    #[test]
    fn snapshot_round_trip_is_deterministic() {
        let mut ledger = DirectiveLedger::for_network("alpha");
        ledger.ingest("a", directive("a", "pending", None), 100);
        ledger.ingest("a", directive("a", "done", None), 100);
        ledger.consume("a", "done").unwrap();
        ledger.commit_checkpoint(
            "a",
            ChainCheckpoint {
                height: 1,
                latest: "11".repeat(32),
            },
        );
        let first = serde_json::to_string(&ledger.snapshot()).unwrap();
        let restored = DirectiveLedger::from_snapshot(ledger.snapshot()).unwrap();
        let second = serde_json::to_string(&restored.snapshot()).unwrap();
        assert_eq!(first, second);
        assert_eq!(restored.network_name(), Some("alpha"));
        assert_eq!(restored.checkpoint("a").unwrap().height, 1);
        assert!(restored.is_consumed("a", "done"));
        assert_eq!(restored.pending_for_at("cisvr", 100).len(), 1);
    }

    #[test]
    fn atomic_save_and_load_preserves_consumed_tombstones() {
        let _guard = SAVE_TEST_LOCK.lock().unwrap();
        let path =
            std::env::temp_dir().join(format!("asfa-ledger-restart-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut ledger = DirectiveLedger::for_registry(&registry("alpha"));
        let item = directive("a", "once", None);
        ledger.ingest("a", item.clone(), 100);
        ledger.consume("a", "once").unwrap();
        ledger.save_atomic(&path).unwrap();
        let mut restored = DirectiveLedger::load_for_registry(&path, &registry("alpha")).unwrap();
        assert_eq!(restored.ingest("a", item, 100), IngestOutcome::Consumed);
        assert!(DirectiveLedger::load_for_registry(&path, &registry("beta")).is_err());
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn atomic_save_preserves_preexisting_temporary_symlink() {
        let _guard = SAVE_TEST_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "asfa-ledger-temporary-symlink-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let state = root.join("state.json");
        let victim = root.join("victim.json");
        fs::write(&victim, "sentinel\n").unwrap();
        let serial = NEXT_TEMP_FILE.load(Ordering::Relaxed);
        let temporary = state.with_extension(format!("tmp-{}-{serial}", std::process::id()));
        std::os::unix::fs::symlink(&victim, &temporary).unwrap();

        let ledger = DirectiveLedger::for_registry(&registry("alpha"));
        ledger.save_atomic(&state).unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "sentinel\n");
        assert!(fs::symlink_metadata(&temporary)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!fs::symlink_metadata(&state)
            .unwrap()
            .file_type()
            .is_symlink());
        DirectiveLedger::load_for_registry(&state, &registry("alpha")).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn atomic_save_exhaustion_preserves_every_collision() {
        let _guard = SAVE_TEST_LOCK.lock().unwrap();
        let root = std::env::temp_dir().join(format!(
            "asfa-ledger-temporary-exhaustion-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let state = root.join("state.json");
        let first_serial = NEXT_TEMP_FILE.load(Ordering::Relaxed);
        for offset in 0..MAX_TEMP_FILE_ATTEMPTS {
            let temporary = state.with_extension(format!(
                "tmp-{}-{}",
                std::process::id(),
                first_serial + offset
            ));
            fs::write(temporary, "sentinel\n").unwrap();
        }

        let ledger = DirectiveLedger::for_registry(&registry("alpha"));
        let error = ledger.save_atomic(&state).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("after 128 attempts"));
        assert!(!state.exists());
        for offset in 0..MAX_TEMP_FILE_ATTEMPTS {
            let temporary = state.with_extension(format!(
                "tmp-{}-{}",
                std::process::id(),
                first_serial + offset
            ));
            assert_eq!(fs::read_to_string(temporary).unwrap(), "sentinel\n");
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn restore_rejects_pending_consumed_overlap() {
        let item = directive("a", "same", None);
        let snapshot = LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            network_name: None,
            policy_hash: None,
            directives: vec![DirectiveEntry {
                session: "a".into(),
                directive: item,
            }],
            consumed: vec![ConsumedKey {
                session: "a".into(),
                id: "same".into(),
            }],
            checkpoints: vec![],
            receipts: vec![],
            dead_letters: vec![],
            tickets: None,
        };
        assert!(matches!(
            DirectiveLedger::from_snapshot(snapshot),
            Err(RestoreError::ConsumedPending { session, id }) if session == "a" && id == "same"
        ));
    }

    #[test]
    fn restore_rejects_duplicate_and_malformed_checkpoints() {
        let duplicate = LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            network_name: Some("alpha".into()),
            policy_hash: None,
            directives: vec![],
            consumed: vec![],
            checkpoints: vec![
                CheckpointEntry {
                    session: "a".into(),
                    height: 0,
                    latest: GENESIS_HASH.into(),
                },
                CheckpointEntry {
                    session: "a".into(),
                    height: 1,
                    latest: "11".repeat(32),
                },
            ],
            receipts: vec![],
            dead_letters: vec![],
            tickets: None,
        };
        assert!(matches!(
            DirectiveLedger::from_snapshot(duplicate),
            Err(RestoreError::DuplicateCheckpoint { session }) if session == "a"
        ));

        let malformed = LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            network_name: Some("alpha".into()),
            policy_hash: None,
            directives: vec![],
            consumed: vec![],
            checkpoints: vec![CheckpointEntry {
                session: "a".into(),
                height: 0,
                latest: "11".repeat(32),
            }],
            receipts: vec![],
            dead_letters: vec![],
            tickets: None,
        };
        assert!(matches!(
            DirectiveLedger::from_snapshot(malformed),
            Err(RestoreError::InvalidEntry(_))
        ));
    }

    #[test]
    fn resource_limits_preserve_pending_work_and_replay_tombstones() {
        let limits = ResourceLimits {
            max_pending_directives: 2,
            max_consumed_tombstones: 1,
            max_directives_per_outbox: 2,
        };
        let mut ledger = DirectiveLedger::new().with_limits(limits);
        assert_eq!(
            ledger.ingest("a", directive("a", "one", None), 100),
            IngestOutcome::Inserted
        );
        assert_eq!(
            ledger.ingest("a", directive("a", "two", None), 100),
            IngestOutcome::Inserted
        );
        assert_eq!(
            ledger.ingest("a", directive("a", "three", None), 100),
            IngestOutcome::OverCapacity
        );
        assert!(ledger.consume("a", "one").unwrap().is_some());
        assert_eq!(
            ledger.consume("a", "two"),
            Err(CapacityError::ConsumedTombstones { limit: 1 })
        );
        assert_eq!(ledger.pending_for_at("cisvr", 100)[0].id, "two");
        assert_eq!(
            ledger.ingest("a", directive("a", "one", None), 100),
            IngestOutcome::Consumed
        );
    }

    #[test]
    fn restore_enforces_local_cardinality_limits() {
        let snapshot = LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            network_name: Some("alpha".into()),
            policy_hash: None,
            directives: vec![DirectiveEntry {
                session: "a".into(),
                directive: directive("a", "one", None),
            }],
            consumed: vec![],
            checkpoints: vec![],
            receipts: vec![],
            dead_letters: vec![],
            tickets: None,
        };
        let limits = ResourceLimits {
            max_pending_directives: 0,
            ..ResourceLimits::default()
        };
        assert!(matches!(
            DirectiveLedger::from_snapshot_with_limits(snapshot, limits),
            Err(RestoreError::ResourceLimit(
                CapacityError::PendingDirectives { limit: 0 }
            ))
        ));
    }

    #[test]
    fn snapshot_parser_rejects_duplicate_members() {
        let path = std::env::temp_dir().join(format!(
            "asfa-ledger-duplicate-json-{}.json",
            std::process::id()
        ));
        let _ = fs::remove_file(&path);
        fs::write(
            &path,
            format!(
                r#"{{"schema_version":"{LEDGER_SCHEMA_VERSION}","schema_version":"other","directives":[],"consumed":[],"checkpoints":[]}}"#
            ),
        )
        .unwrap();
        let error = DirectiveLedger::load(&path).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        fs::remove_file(path).unwrap();
    }
}
