//! Outbox transport, verification, and directive ingestion.

#![forbid(unsafe_code)]

pub mod chain;
pub mod egress;
pub mod execution;
pub mod ingest;
pub mod ledger;
pub mod model;
pub mod output_paths;
pub mod poller;
pub mod state_lock;
pub mod strict_json;
pub mod wave;

pub use chain::{
    append_block, append_directives, make_block, verified_directives, verify_chain, ChainError,
};
pub use egress::{address_class, validate_ip, EgressError, EgressPolicy, Resolve, SystemResolver};
pub use execution::{
    execute_wave, ExecutionError, ExecutionResult, ExecutionSummary, WaveExecutionReport,
};
pub use ingest::{ingest_outbox, IngestError};
pub use ledger::{
    CapacityError, ChainCheckpoint, CheckpointEntry, ConsumedKey, DirectiveEntry, DirectiveLedger,
    ExecutionCommitError, IngestOutcome, LedgerSnapshot, ResourceLimits, RestoreError,
};
pub use model::*;
pub use output_paths::{ensure_distinct, OutputPath, OutputPathError};
pub use poller::{PollDeadlineError, Poller};
pub use state_lock::StateLock;
pub use wave::{
    compute_wave_plan_hash, ledger_digest, plan_wave, verify_wave_plan, WaveError, WaveJob,
    WavePlan, WaveSourceStats,
};
