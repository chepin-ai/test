//! Outbox transport, verification, and directive ingestion.

#![forbid(unsafe_code)]

pub mod chain;
pub mod ingest;
pub mod ledger;
pub mod model;
pub mod poller;
pub mod strict_json;

pub use chain::{
    append_block, append_directives, make_block, verified_directives, verify_chain, ChainError,
};
pub use ingest::ingest_outbox;
pub use ledger::{
    ChainCheckpoint, CheckpointEntry, ConsumedKey, DirectiveEntry, DirectiveLedger, IngestOutcome,
    LedgerSnapshot, RestoreError,
};
pub use model::*;
pub use poller::Poller;
