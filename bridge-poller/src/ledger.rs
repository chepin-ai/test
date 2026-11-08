use crate::model::Directive;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Read};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

pub const LEDGER_SCHEMA_VERSION: &str = "asfa-directive-ledger/v1";
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct LedgerSnapshot {
    pub schema_version: String,
    pub directives: Vec<DirectiveEntry>,
    pub consumed: Vec<ConsumedKey>,
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
    #[error("consumed directive is also pending: {session}/{id}")]
    ConsumedPending { session: String, id: String },
}

/// Idempotent directive store with consumption tombstones. Snapshot persistence
/// is explicit: callers must save after mutations if restart durability is needed.
#[derive(Default)]
pub struct DirectiveLedger {
    directives: BTreeMap<DirectiveKey, Directive>,
    consumed: BTreeSet<DirectiveKey>,
}

impl DirectiveLedger {
    pub fn new() -> Self {
        Self::default()
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

    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
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
        }
    }

    pub fn from_snapshot(snapshot: LedgerSnapshot) -> Result<Self, RestoreError> {
        if snapshot.schema_version != LEDGER_SCHEMA_VERSION {
            return Err(RestoreError::UnsupportedSchema(snapshot.schema_version));
        }
        let mut ledger = Self::new();
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

    pub fn load(path: &Path) -> io::Result<Self> {
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
        let snapshot: LedgerSnapshot = serde_json::from_slice(&bytes)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        Self::from_snapshot(snapshot)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }
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
        let mut ledger = DirectiveLedger::new();
        ledger.ingest("a", directive("a", "pending", None), 100);
        ledger.ingest("a", directive("a", "done", None), 100);
        ledger.consume("a", "done");
        let first = serde_json::to_string(&ledger.snapshot()).unwrap();
        let restored = DirectiveLedger::from_snapshot(ledger.snapshot()).unwrap();
        let second = serde_json::to_string(&restored.snapshot()).unwrap();
        assert_eq!(first, second);
        assert!(restored.is_consumed("a", "done"));
        assert_eq!(restored.pending_for_at("cisvr", 100).len(), 1);
    }

    #[test]
    fn atomic_save_and_load_preserves_consumed_tombstones() {
        let path =
            std::env::temp_dir().join(format!("asfa-ledger-restart-{}.json", std::process::id()));
        let _ = fs::remove_file(&path);
        let mut ledger = DirectiveLedger::new();
        let item = directive("a", "once", None);
        ledger.ingest("a", item.clone(), 100);
        ledger.consume("a", "once");
        ledger.save_atomic(&path).unwrap();
        let mut restored = DirectiveLedger::load(&path).unwrap();
        assert_eq!(restored.ingest("a", item, 100), IngestOutcome::Consumed);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn restore_rejects_pending_consumed_overlap() {
        let item = directive("a", "same", None);
        let snapshot = LedgerSnapshot {
            schema_version: LEDGER_SCHEMA_VERSION.into(),
            directives: vec![DirectiveEntry {
                session: "a".into(),
                directive: item,
            }],
            consumed: vec![ConsumedKey {
                session: "a".into(),
                id: "same".into(),
            }],
        };
        assert!(matches!(
            DirectiveLedger::from_snapshot(snapshot),
            Err(RestoreError::ConsumedPending { session, id }) if session == "a" && id == "same"
        ));
    }
}
