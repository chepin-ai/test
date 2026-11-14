use crate::chain::ChainError;
use crate::model::{Directive, Outbox, Registry, GENESIS_HASH};
use crate::strict_json;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

pub const LEDGER_SCHEMA_VERSION: &str = "asfa-directive-ledger/v3";
pub const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_PENDING_DIRECTIVES: usize = 4096;
pub const DEFAULT_MAX_CONSUMED_TOMBSTONES: usize = 16384;
pub const DEFAULT_MAX_DIRECTIVES_PER_OUTBOX: usize = 1024;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

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
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RestoreError {
    #[error("unsupported ledger schema: {0}")]
    UnsupportedSchema(String),
    #[error("invalid ledger entry: {0}")]
    InvalidEntry(String),
    #[error("duplicate directive in snapshot: {session}/{id}")]
    DuplicateDirective { session: String, id: String },
    #[error("duplicate consumed key in snapshot: {session}/{id}")]
    DuplicateConsumed { session: String, id: String },
    #[error("duplicate chain checkpoint in snapshot: {session}")]
    DuplicateCheckpoint { session: String },
    #[error("consumed directive is also pending: {session}/{id}")]
    ConsumedPending { session: String, id: String },
    #[error("ledger resource limit: {0}")]
    ResourceLimit(#[from] CapacityError),
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
        LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
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
        }
    }

    pub fn from_snapshot(snapshot: LedgerSnapshot) -> Result<Self, RestoreError> {
        Self::from_snapshot_with_limits(snapshot, ResourceLimits::default())
    }

    pub fn from_snapshot_with_limits(
        snapshot: LedgerSnapshot,
        limits: ResourceLimits,
    ) -> Result<Self, RestoreError> {
        if snapshot.schema_version != LEDGER_SCHEMA_VERSION {
            return Err(RestoreError::UnsupportedSchema(snapshot.schema_version));
        }
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
        for (session, id) in &ledger.consumed {
            if ledger
                .directives
                .contains_key(&(session.clone(), id.clone()))
            {
                return Err(RestoreError::ConsumedPending {
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
        Ok(ledger)
    }

    /// Atomically replace the snapshot within the destination filesystem.
    pub fn save_atomic(&self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let serial = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
        let temporary = path.with_extension(format!("tmp-{}-{serial}", std::process::id()));
        let rendered =
            serde_json::to_string_pretty(&self.snapshot()).map_err(io::Error::other)? + "\n";
        if rendered.len() as u64 > MAX_LEDGER_BYTES {
            let _ = fs::remove_file(&temporary);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                CapacityError::SnapshotBytes {
                    limit: MAX_LEDGER_BYTES,
                    actual: rendered.len(),
                },
            ));
        }
        fs::write(&temporary, rendered)?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
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
        if snapshot.schema_version != LEDGER_SCHEMA_VERSION {
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
