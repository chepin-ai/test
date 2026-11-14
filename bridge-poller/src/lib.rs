//! Outbox transport, verification, and directive ingestion.

#![forbid(unsafe_code)]

pub mod chain;
pub mod ingest;
pub mod ledger;
pub mod model;
pub mod poller;
pub mod state_lock;
pub mod strict_json;
pub mod wave;

pub use chain::{
    append_block, append_directives, make_block, verified_directives, verify_chain, ChainError,
};
pub use ingest::{ingest_outbox, IngestError};
pub use ledger::{
    CapacityError, ChainCheckpoint, CheckpointEntry, ConsumedKey, DirectiveEntry, DirectiveLedger,
    IngestOutcome, LedgerSnapshot, ResourceLimits, RestoreError,
};
pub use model::*;
pub use poller::{PollDeadlineError, Poller};
pub use state_lock::StateLock;
pub use wave::{plan_wave, WaveError, WaveJob, WavePlan, WaveSourceStats};
