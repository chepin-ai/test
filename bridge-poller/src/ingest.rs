use crate::chain::{verified_directives, ChainError};
use crate::ledger::{DirectiveLedger, IngestOutcome};
use crate::model::{IngestionEvent, IngestionReport, Outbox};

/// Verify the complete outbox before applying any directive. No partial ingestion
/// occurs when chain or directive verification fails.
pub fn ingest_outbox(
    ledger: &mut DirectiveLedger,
    outbox: &Outbox,
    now_epoch: u64,
) -> Result<IngestionReport, ChainError> {
    let directives = verified_directives(outbox)?;
    let checkpoint = ledger.checkpoint_for(outbox)?;
    let mut report = IngestionReport::default();
    for directive in directives {
        let id = directive.id.clone();
        let outcome = ledger.ingest(&outbox.session, directive, now_epoch);
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
        };
        report.events.push(IngestionEvent {
            session: outbox.session.clone(),
            id,
            outcome: name.into(),
            message,
        });
    }
    ledger.commit_checkpoint(&outbox.session, checkpoint);
    report.chain_checkpoints = 1;
    report.pending = ledger.len();
    report.tombstones = ledger.consumed_len();
    Ok(report)
}
