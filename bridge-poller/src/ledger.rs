use crate::chain::ChainError;
use crate::model::{Directive, Outbox, GENESIS_HASH};
use crate::strict_json;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

pub const LEDGER_SCHEMA_VERSION: &str = "asfa-directive-ledger/v2";
pub const MAX_LEDGER_BYTES: u64 = 16 * 1024 * 1024;
static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    Inserted,
    Duplicate,
    Consumed,
    Conflict,
    Expired,
    Invalid(String),
}

type DirectiveKey = (String, String);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct DirectiveEntry {
    pub session: String,
    pub directive: Directive,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ConsumedKey {
    pub session: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChainCheckpoint {
    pub height: u64,
    pub latest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CheckpointEntry {
    pub session: String,
    pub height: u64,
    pub latest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct LedgerSnapshot {
    pub schema_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_name: Option<String>,
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
}

/// Idempotent directive store with consumption tombstones and per-session chain
/// checkpoints. Persistence is explicit and supports a single writer; atomic
/// rename prevents torn files but does not provide multi-process compare-and-swap.
#[derive(Default)]
pub struct DirectiveLedger {
    network_name: Option<String>,
    directives: BTreeMap<DirectiveKey, Directive>,
    consumed: BTreeSet<DirectiveKey>,
    checkpoints: BTreeMap<String, ChainCheckpoint>,
}

impl DirectiveLedger {
    /// Construct an unbound in-memory ledger for isolated library use. Network
    /// CLI callers use `for_network` or `load_for_network` instead.
    pub fn new() -> Self {
        Self::default()
    }

    pub fn for_network(network_name: impl Into<String>) -> Self {
        Self {
            network_name: Some(network_name.into()),
            ..Self::default()
        }
    }

    pub fn network_name(&self) -> Option<&str> {
        self.network_name.as_deref()
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
        self.directives.insert(key, directive);
        IngestOutcome::Inserted
    }

    pub fn pending_for_at(&self, target: &str, now_epoch: u64) -> Vec<&Directive> {
        self.directives
            .values()
            .filter(|directive| {
                (directive.to == target || directive.to == "*")
                    && directive
                        .expires_epoch
                        .is_none_or(|expires| expires > now_epoch)
            })
            .collect()
    }

    /// Consuming removes the directive and leaves a tombstone so replaying the
    /// same session/ID cannot reinsert it during this ledger's lifetime.
    pub fn consume(&mut self, session: &str, id: &str) -> Option<Directive> {
        let key = (session.to_owned(), id.to_owned());
        let directive = self.directives.remove(&key)?;
        self.consumed.insert(key);
        Some(directive)
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
        let mut ledger = Self {
            network_name: snapshot.network_name,
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
        fs::write(&temporary, rendered)?;
        if let Err(error) = fs::rename(&temporary, path) {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    fn read_snapshot(path: &Path) -> io::Result<LedgerSnapshot> {
        let file = fs::File::open(path)?;
        if file.metadata()?.len() > MAX_LEDGER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ledger exceeds {MAX_LEDGER_BYTES} bytes"),
            ));
        }
        let mut bytes = Vec::new();
        file.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_LEDGER_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("ledger exceeds {MAX_LEDGER_BYTES} bytes"),
            ));
        }
        strict_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn load(path: &Path) -> io::Result<Self> {
        Self::from_snapshot(Self::read_snapshot(path)?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub fn load_for_network(path: &Path, expected_network: &str) -> io::Result<Self> {
        let snapshot = Self::read_snapshot(path)?;
        if snapshot.network_name.as_deref() != Some(expected_network) {
            let actual = snapshot.network_name.as_deref().unwrap_or("<unbound>");
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ledger network mismatch: expected={expected_network}, actual={actual}; refusing implicit migration"
                ),
            ));
        }
        Self::from_snapshot(snapshot)
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
        assert!(ledger.consume("a", "once").is_some());
        assert!(ledger.consume("a", "once").is_none());
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
        assert!(ledger.consume("a/b", "c").is_some());
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
        ledger.consume("a", "done");
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
        let mut ledger = DirectiveLedger::for_network("alpha");
        let item = directive("a", "once", None);
        ledger.ingest("a", item.clone(), 100);
        ledger.consume("a", "once");
        ledger.save_atomic(&path).unwrap();
        let mut restored = DirectiveLedger::load_for_network(&path, "alpha").unwrap();
        assert_eq!(restored.ingest("a", item, 100), IngestOutcome::Consumed);
        assert!(DirectiveLedger::load_for_network(&path, "beta").is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn restore_rejects_pending_consumed_overlap() {
        let item = directive("a", "same", None);
        let snapshot = LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            network_name: None,
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
