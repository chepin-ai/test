use crate::chain::{verified_directives, ChainError};
use crate::ledger::{CapacityError, DirectiveLedger, IngestOutcome};
use crate::model::{IngestionEvent, IngestionReport, Outbox};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum IngestError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Capacity(#[from] CapacityError),
}

/// Verify the complete outbox and apply it to a staged ledger. Any chain,
/// directive, or capacity failure discards the entire batch: no successfully
/// processed prefix can become a partial committed state.
pub fn ingest_outbox(
    ledger: &mut DirectiveLedger,
    outbox: &Outbox,
    now_epoch: u64,
) -> Result<IngestionReport, IngestError> {
    let directives = verified_directives(outbox)?;
    let limits = ledger.limits();
    if directives.len() > limits.max_directives_per_outbox {
        return Err(CapacityError::DirectivesPerOutbox {
            limit: limits.max_directives_per_outbox,
            actual: directives.len(),
        }
        .into());
    }
    let checkpoint = ledger.checkpoint_for(outbox)?;
    let mut staged = ledger.clone();
    let mut report = IngestionReport::default();
    for directive in directives {
        let id = directive.id.clone();
        let outcome = staged.ingest(&outbox.session, directive, now_epoch);
        let (name, message) = match &outcome {
            IngestOutcome::Inserted => {
                report.inserted += 1;
                ("inserted", None)
            }
            IngestOutcome::Duplicate => {
                report.duplicate += 1;
                ("duplicate", None)
            }
            IngestOutcome::Consumed => {
                report.replayed_consumed += 1;
                ("consumed", None)
            }
            IngestOutcome::Conflict => {
                report.conflict += 1;
                ("conflict", None)
            }
            IngestOutcome::Expired => {
                report.expired += 1;
                ("expired", None)
            }
            IngestOutcome::Invalid(reason) => {
                report.invalid += 1;
                ("invalid", Some(reason.clone()))
            }
            IngestOutcome::OverCapacity => {
                return Err(CapacityError::PendingDirectives {
                    limit: limits.max_pending_directives,
                }
                .into());
            }
        };
        report.events.push(IngestionEvent {
            session: outbox.session.clone(),
            id,
            outcome: name.into(),
            message,
        });
    }
    staged.commit_checkpoint(&outbox.session, checkpoint);
    report.chain_checkpoints = 1;
    report.pending = staged.len();
    report.tombstones = staged.consumed_len();
    *ledger = staged;
    Ok(report)
}
