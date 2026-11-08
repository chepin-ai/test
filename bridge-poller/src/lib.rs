//! Outbox transport, verification, and directive ingestion.

#![forbid(unsafe_code)]

pub mod chain;
pub mod ledger;
pub mod model;
pub mod poller;

pub use chain::{
    append_block, append_directives, make_block, verified_directives, verify_chain, ChainError,
};
pub use ledger::{
    ConsumedKey, DirectiveEntry, DirectiveLedger, IngestOutcome, LedgerSnapshot, RestoreError,
};
pub use model::*;
pub use poller::Poller;
