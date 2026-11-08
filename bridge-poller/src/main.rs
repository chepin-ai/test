use asfa_bridge_poller::{
    ingest_outbox, BridgeReport, DirectiveLedger, IngestionReport, Poller, Registry, SessionPoll,
};
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_epoch() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn usage() {
    println!(
        "asfa-bridge-poller --config <sessions.json> [--out report.json] [--now EPOCH] \
         [--state ledger.json] [--consume-session NAME --consume-id ID] [--fail-on-error]"
    );
}

fn main() {
    if let Err(error) = run() {
        eprintln!("bridge-poller: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut config = PathBuf::from("config/sessions.json");
    let mut out: Option<PathBuf> = None;
    let mut now: Option<u64> = None;
    let mut state: Option<PathBuf> = None;
    let mut consume_session: Option<String> = None;
    let mut consume_id: Option<String> = None;
    let mut fail_on_error = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = args.next().ok_or("--config requires a path")?.into(),
            "--out" => out = Some(args.next().ok_or("--out requires a path")?.into()),
            "--now" => now = Some(args.next().ok_or("--now requires epoch seconds")?.parse()?),
            "--state" => state = Some(args.next().ok_or("--state requires a path")?.into()),
            "--consume-session" => {
                consume_session = Some(args.next().ok_or("--consume-session requires a name")?)
            }
            "--consume-id" => consume_id = Some(args.next().ok_or("--consume-id requires an ID")?),
            "--fail-on-error" => fail_on_error = true,
            "--help" | "-h" => {
                usage();
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    if consume_session.is_some() != consume_id.is_some() {
        return Err("--consume-session and --consume-id must be used together".into());
    }
    if consume_session.is_some() && state.is_none() {
        return Err("consuming a directive requires --state".into());
    }
    if let (Some(state_path), Some(out_path)) = (&state, &out) {
        if state_path == out_path {
            return Err("--state and --out must be different files".into());
        }
    }
    let now = match now {
        Some(value) => value,
        None => now_epoch()?,
    };

    let registry: Registry = serde_json::from_str(&fs::read_to_string(&config)?)?;
    let poller = Poller::new();
    let report = if let Some(state_path) = state {
        let mut ledger = match DirectiveLedger::load(&state_path) {
            Ok(ledger) => ledger,
            Err(error) if error.kind() == io::ErrorKind::NotFound => DirectiveLedger::new(),
            Err(error) => return Err(error.into()),
        };
        let mut ingestion = IngestionReport::default();
        let mut records = Vec::new();
        for SessionPoll { record, outbox } in poller.poll_registry_detailed(&registry, now) {
            records.push(record);
            if let Some(outbox) = outbox {
                ingestion.merge(ingest_outbox(&mut ledger, &outbox, now)?);
            }
        }
        if let (Some(session), Some(id)) = (consume_session, consume_id) {
            let consumed = ledger.consume(&session, &id).is_some();
            ingestion.consume_result = Some(if consumed { "consumed" } else { "not_found" }.into());
        }
        ingestion.pending = ledger.len();
        ingestion.tombstones = ledger.consumed_len();
        ledger.save_atomic(&state_path)?;
        ingestion.state_saved = true;
        let mut report = BridgeReport::new(registry.network_name.clone(), now, records);
        report.ingestion = Some(ingestion);
        report
    } else {
        poller.poll_registry(&registry, now)
    };

    let rendered = serde_json::to_string_pretty(&report)? + "\n";
    if let Some(path) = out {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, rendered)?;
    } else {
        print!("{rendered}");
    }
    eprintln!(
        "polled={} verified={} failed={}",
        report.summary.total, report.summary.verified, report.summary.failed
    );
    let ingestion_failed = report.ingestion.as_ref().is_some_and(|ingestion| {
        ingestion.conflict > 0
            || ingestion.invalid > 0
            || ingestion.consume_result.as_deref() == Some("not_found")
    });
    if fail_on_error && (report.summary.failed > 0 || ingestion_failed) {
        return Err("poll or ingestion verification failed".into());
    }
    Ok(())
}
