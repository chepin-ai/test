use asfa_bridge_poller::ledger::{
    DEFAULT_MAX_CONSUMED_TOMBSTONES, DEFAULT_MAX_DIRECTIVES_PER_OUTBOX,
    DEFAULT_MAX_PENDING_DIRECTIVES,
};
use asfa_bridge_poller::wave::{DEFAULT_WAVE_MAX_JOBS, DEFAULT_WAVE_MAX_PER_SOURCE};
use asfa_bridge_poller::{
    ingest_outbox, plan_wave, strict_json, BridgeReport, DirectiveLedger, IngestionReport, Poller,
    Registry, ResourceLimits, SessionPoll, StateLock, WavePlan,
};
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_REGISTRY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_REGISTRY_SESSIONS: usize = 64;
const DEFAULT_POLL_TIMEOUT_MS: usize = 60_000;

fn now_epoch() -> Result<u64, Box<dyn Error>> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn usage() {
    println!(
        "asfa-bridge-poller --config <sessions.json> [--out report.json] [--now EPOCH] \
         [--state ledger.json] [--consume-session NAME --consume-id ID] [--fail-on-error] \
         [--max-pending N] [--max-tombstones N] [--max-outbox-directives N] [--poll-timeout-ms N] \
         [--wave-out plan.json --wave-target NAME] [--wave-max-jobs N] [--wave-max-per-source N]"
    );
}

fn parse_cap(value: Option<String>, default: usize, flag: &str) -> Result<usize, Box<dyn Error>> {
    let Some(value) = value else {
        return Ok(default);
    };
    let parsed: usize = value.parse()?;
    if parsed == 0 || parsed > default {
        return Err(format!("{flag} must be in 1..={default}").into());
    }
    Ok(parsed)
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
    let mut max_pending = None;
    let mut max_tombstones = None;
    let mut max_outbox_directives = None;
    let mut poll_timeout_ms = None;
    let mut wave_out: Option<PathBuf> = None;
    let mut wave_target = "qfos".to_owned();
    let mut wave_max_jobs = None;
    let mut wave_max_per_source = None;
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
            "--max-pending" => max_pending = Some(args.next().ok_or("--max-pending requires N")?),
            "--max-tombstones" => {
                max_tombstones = Some(args.next().ok_or("--max-tombstones requires N")?)
            }
            "--max-outbox-directives" => {
                max_outbox_directives =
                    Some(args.next().ok_or("--max-outbox-directives requires N")?)
            }
            "--poll-timeout-ms" => {
                poll_timeout_ms = Some(args.next().ok_or("--poll-timeout-ms requires N")?)
            }
            "--wave-out" => {
                wave_out = Some(args.next().ok_or("--wave-out requires a path")?.into())
            }
            "--wave-target" => wave_target = args.next().ok_or("--wave-target requires a name")?,
            "--wave-max-jobs" => {
                wave_max_jobs = Some(args.next().ok_or("--wave-max-jobs requires N")?)
            }
            "--wave-max-per-source" => {
                wave_max_per_source = Some(args.next().ok_or("--wave-max-per-source requires N")?)
            }
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
    if wave_out.is_some() && state.is_none() {
        return Err("--wave-out requires --state so plans bind to a verified ledger".into());
    }
    if let (Some(state_path), Some(out_path)) = (&state, &out) {
        if state_path == out_path {
            return Err("--state and --out must be different files".into());
        }
    }
    if let Some(wave_path) = &wave_out {
        if state.as_ref() == Some(wave_path) || out.as_ref() == Some(wave_path) {
            return Err("--wave-out must differ from --state and --out".into());
        }
    }
    let limits = ResourceLimits {
        max_pending_directives: parse_cap(
            max_pending,
            DEFAULT_MAX_PENDING_DIRECTIVES,
            "--max-pending",
        )?,
        max_consumed_tombstones: parse_cap(
            max_tombstones,
            DEFAULT_MAX_CONSUMED_TOMBSTONES,
            "--max-tombstones",
        )?,
        max_directives_per_outbox: parse_cap(
            max_outbox_directives,
            DEFAULT_MAX_DIRECTIVES_PER_OUTBOX,
            "--max-outbox-directives",
        )?,
    };
    let wave_max_jobs = parse_cap(wave_max_jobs, DEFAULT_WAVE_MAX_JOBS, "--wave-max-jobs")?;
    let wave_max_per_source = parse_cap(
        wave_max_per_source,
        DEFAULT_WAVE_MAX_PER_SOURCE,
        "--wave-max-per-source",
    )?;
    let poll_timeout_ms = parse_cap(
        poll_timeout_ms,
        DEFAULT_POLL_TIMEOUT_MS,
        "--poll-timeout-ms",
    )?;
    let now = match now {
        Some(value) => value,
        None => now_epoch()?,
    };
    let poll_deadline = Instant::now() + Duration::from_millis(poll_timeout_ms as u64);

    let registry: Registry = strict_json::from_path(&config, MAX_REGISTRY_BYTES)?;
    if registry.network_name.trim().is_empty() {
        return Err("registry network_name must not be empty".into());
    }
    if registry.sessions.len() > MAX_REGISTRY_SESSIONS {
        return Err(format!(
            "registry session capacity exceeded: limit={MAX_REGISTRY_SESSIONS}, actual={}",
            registry.sessions.len()
        )
        .into());
    }

    // Acquire the stable sidecar before loading and retain it through state,
    // report, and wave output. A contested writer fails instead of overwriting.
    let _state_lock = state
        .as_ref()
        .map(|path| StateLock::acquire(path))
        .transpose()?;
    let poller = Poller::new();
    let (report, wave_plan): (BridgeReport, Option<WavePlan>) = if let Some(state_path) = state {
        let mut ledger =
            match DirectiveLedger::load_for_registry_with_limits(&state_path, &registry, limits) {
                Ok(ledger) => ledger,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    DirectiveLedger::for_registry(&registry).with_limits(limits)
                }
                Err(error) => return Err(error.into()),
            };
        let mut ingestion = IngestionReport::default();
        let mut records = Vec::new();
        let polls = poller.poll_registry_detailed_with_deadline(&registry, now, poll_deadline)?;
        for SessionPoll { record, outbox } in polls {
            records.push(record);
            if let Some(outbox) = outbox {
                ingestion.merge(ingest_outbox(&mut ledger, &outbox, now)?);
            }
        }
        if let (Some(session), Some(id)) = (consume_session, consume_id) {
            let consumed = ledger.consume(&session, &id)?.is_some();
            ingestion.consume_result = Some(if consumed { "consumed" } else { "not_found" }.into());
        }
        ingestion.pending = ledger.len();
        ingestion.tombstones = ledger.consumed_len();
        let wave_plan = wave_out
            .as_ref()
            .map(|_| {
                plan_wave(
                    &ledger,
                    &wave_target,
                    now,
                    wave_max_jobs,
                    wave_max_per_source,
                )
            })
            .transpose()?;
        Poller::ensure_deadline(poll_deadline, "after ingestion and wave planning")?;
        ledger.save_atomic(&state_path)?;
        ingestion.state_saved = true;
        let mut report = BridgeReport::new(registry.network_name.clone(), now, records);
        report.ingestion = Some(ingestion);
        (report, wave_plan)
    } else {
        let polls = poller.poll_registry_detailed_with_deadline(&registry, now, poll_deadline)?;
        let records = polls.into_iter().map(|result| result.record).collect();
        (
            BridgeReport::new(registry.network_name.clone(), now, records),
            None,
        )
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
    if let (Some(path), Some(plan)) = (wave_out, wave_plan) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(&plan)? + "\n")?;
        eprintln!(
            "wave_jobs={} wave_deferred={} plan_hash={}",
            plan.jobs.len(),
            plan.deferred,
            plan.plan_hash
        );
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
