use crate::model::Directive;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngestOutcome {
    Inserted,
    Duplicate,
    Expired,
    Invalid(String),
}

/// Idempotent directive store. IDs are scoped by session to prevent collisions.
#[derive(Default)]
pub struct DirectiveLedger {
    directives: BTreeMap<String, Directive>,
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

    pub fn ingest(&mut self, session: &str, directive: Directive, now_epoch: u64) -> IngestOutcome {
        if directive.id.trim().is_empty() {
            return IngestOutcome::Invalid("directive id must not be empty".into());
        }
        if directive
            .expires_epoch
            .is_some_and(|expires| expires <= now_epoch)
        {
            return IngestOutcome::Expired;
        }
        let key = format!("{session}/{}", directive.id);
        if self.directives.contains_key(&key) {
            return IngestOutcome::Duplicate;
        }
        self.directives.insert(key, directive);
        IngestOutcome::Inserted
    }

    pub fn pending_for(&self, target: &str) -> Vec<&Directive> {
        self.directives
            .values()
            .filter(|directive| directive.to == target || directive.to == "*")
            .collect()
    }

    /// Consuming removes the directive, making replay impossible through this API.
    pub fn consume(&mut self, session: &str, id: &str) -> Option<Directive> {
        self.directives.remove(&format!("{session}/{id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn directive(id: &str, expires_epoch: Option<u64>) -> Directive {
        Directive {
            id: id.into(),
            from: "a".into(),
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
            ledger.ingest("a", directive("one", Some(200)), 100),
            IngestOutcome::Inserted
        );
        assert_eq!(
            ledger.ingest("a", directive("one", Some(200)), 100),
            IngestOutcome::Duplicate
        );
        assert_eq!(
            ledger.ingest("a", directive("old", Some(99)), 100),
            IngestOutcome::Expired
        );
        assert_eq!(ledger.len(), 1);
    }

    #[test]
    fn consumption_is_single_use() {
        let mut ledger = DirectiveLedger::new();
        ledger.ingest("a", directive("once", None), 100);
        assert!(ledger.consume("a", "once").is_some());
        assert!(ledger.consume("a", "once").is_none());
    }

    #[test]
    fn same_id_from_different_sessions_does_not_collide() {
        let mut ledger = DirectiveLedger::new();
        ledger.ingest("a", directive("same", None), 100);
        ledger.ingest("b", directive("same", None), 100);
        assert_eq!(ledger.len(), 2);
        assert_eq!(ledger.pending_for("cisvr").len(), 2);
    }
}
