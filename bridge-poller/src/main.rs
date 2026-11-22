use asfa_bridge_poller::ledger::{
    DEFAULT_MAX_CONSUMED_TOMBSTONES, DEFAULT_MAX_DIRECTIVES_PER_OUTBOX,
    DEFAULT_MAX_PENDING_DIRECTIVES,
};
use asfa_bridge_poller::wave::{DEFAULT_WAVE_MAX_JOBS, DEFAULT_WAVE_MAX_PER_SOURCE};
use asfa_bridge_poller::{
    ensure_distinct, execute_ticketed_wave, execute_wave, ingest_outbox, ledger_digest,
    mint_wave_tickets, plan_wave, strict_json, verify_wave_plan, BridgeReport, DirectiveLedger,
    EgressPolicy, IngestionReport, OutputPath, Poller, Registry, ResourceLimits, SessionPoll,
    StateLock, TicketOperationReport, WaveExecutionReport, WavePlan,
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
         [--wave-out plan.json --wave-target NAME] [--wave-max-jobs N] [--wave-max-per-source N] \
         [--execute-wave --execution-out execution.json] [--allow-non-public-egress] \
         [--ticket-mint-root NONCE --ticket-controller NAME --ticket-agent NAME] \
         [--ticketed-execution] [--ticket-transfer ID --ticket-to NAME] \
         [--ticket-revoke-root ID] [--ticket-out ticket-operation.json]"
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
    let mut execute_wave_mode = false;
    let mut execution_out: Option<PathBuf> = None;
    let mut allow_non_public_egress = false;
    let mut ticket_mint_root: Option<String> = None;
    let mut ticket_controller: Option<String> = None;
    let mut ticket_agent: Option<String> = None;
    let mut ticketed_execution = false;
    let mut ticket_transfer: Option<String> = None;
    let mut ticket_to: Option<String> = None;
    let mut ticket_revoke_root: Option<String> = None;
    let mut ticket_out: Option<PathBuf> = None;
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
            "--execute-wave" => execute_wave_mode = true,
            "--allow-non-public-egress" => allow_non_public_egress = true,
            "--execution-out" => {
                execution_out = Some(args.next().ok_or("--execution-out requires a path")?.into())
            }
            "--ticket-mint-root" => {
                ticket_mint_root = Some(args.next().ok_or("--ticket-mint-root requires a nonce")?)
            }
            "--ticket-controller" => {
                ticket_controller = Some(args.next().ok_or("--ticket-controller requires a name")?)
            }
            "--ticket-agent" => {
                ticket_agent = Some(args.next().ok_or("--ticket-agent requires a name")?)
            }
            "--ticketed-execution" => ticketed_execution = true,
            "--ticket-transfer" => {
                ticket_transfer = Some(args.next().ok_or("--ticket-transfer requires an ID")?)
            }
            "--ticket-to" => ticket_to = Some(args.next().ok_or("--ticket-to requires a name")?),
            "--ticket-revoke-root" => {
                ticket_revoke_root = Some(args.next().ok_or("--ticket-revoke-root requires an ID")?)
            }
            "--ticket-out" => {
                ticket_out = Some(args.next().ok_or("--ticket-out requires a path")?.into())
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
    if execute_wave_mode && (wave_out.is_none() || execution_out.is_none()) {
        return Err("--execute-wave requires --wave-out and --execution-out".into());
    }
    if execution_out.is_some() && !execute_wave_mode {
        return Err("--execution-out requires --execute-wave".into());
    }
    let ticket_mutations = usize::from(ticket_mint_root.is_some())
        + usize::from(ticket_transfer.is_some())
        + usize::from(ticket_revoke_root.is_some());
    if ticket_mutations > 1 {
        return Err("ticket mint, transfer, and revoke are mutually exclusive".into());
    }
    if execute_wave_mode && ticket_mutations != 0 {
        return Err(
            "ticket mint, transfer, or revoke cannot be combined with --execute-wave; use --ticketed-execution without a ticket mutation".into(),
        );
    }
    let any_ticket_operation = ticketed_execution || ticket_mutations != 0;
    if any_ticket_operation && (state.is_none() || ticket_out.is_none() || ticket_agent.is_none()) {
        return Err("ticket operations require --state, --ticket-out, and --ticket-agent".into());
    }
    if ticketed_execution && (!execute_wave_mode || ticket_mutations != 0) {
        return Err("--ticketed-execution requires --execute-wave and no ticket mutation".into());
    }
    if ticket_mint_root.is_some()
        && (execute_wave_mode || wave_out.is_none() || ticket_controller.is_none())
    {
        return Err(
            "ticket mint requires --wave-out and --ticket-controller, without --execute-wave"
                .into(),
        );
    }
    if ticket_transfer.is_some() && ticket_to.is_none() {
        return Err("--ticket-transfer requires --ticket-to".into());
    }
    if ticket_to.is_some() && ticket_transfer.is_none() {
        return Err("--ticket-to requires --ticket-transfer".into());
    }
    if ticket_controller.is_some() && ticket_mint_root.is_none() {
        return Err("--ticket-controller requires --ticket-mint-root".into());
    }
    if ticket_agent.is_some() && !any_ticket_operation {
        return Err("--ticket-agent requires a ticket operation".into());
    }
    if ticket_out.is_some() && !any_ticket_operation {
        return Err("--ticket-out requires a ticket operation".into());
    }
    if any_ticket_operation && consume_session.is_some() {
        return Err("ticket operations cannot be combined with legacy consume".into());
    }
    for (flag, value) in [
        ("--ticket-mint-root", ticket_mint_root.as_deref()),
        ("--ticket-controller", ticket_controller.as_deref()),
        ("--ticket-agent", ticket_agent.as_deref()),
        ("--ticket-transfer", ticket_transfer.as_deref()),
        ("--ticket-to", ticket_to.as_deref()),
        ("--ticket-revoke-root", ticket_revoke_root.as_deref()),
    ] {
        if value.is_some_and(|value| value.trim().is_empty()) {
            return Err(format!("{flag} must not be empty").into());
        }
    }
    let state_output = state
        .map(|path| OutputPath::new("--state", path))
        .transpose()?;
    let out_output = out.map(|path| OutputPath::new("--out", path)).transpose()?;
    let wave_output = wave_out
        .map(|path| OutputPath::new("--wave-out", path))
        .transpose()?;
    let execution_output = execution_out
        .map(|path| OutputPath::new("--execution-out", path))
        .transpose()?;
    let ticket_output = ticket_out
        .map(|path| OutputPath::new("--ticket-out", path))
        .transpose()?;
    {
        let mut declared = Vec::new();
        for output in [
            state_output.as_ref(),
            out_output.as_ref(),
            wave_output.as_ref(),
            execution_output.as_ref(),
            ticket_output.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            declared.push(output);
        }
        ensure_distinct(&declared)?;
    }
    let state = state_output.map(OutputPath::into_path);
    let out = out_output.map(OutputPath::into_path);
    let wave_out = wave_output.map(OutputPath::into_path);
    let execution_out = execution_output.map(OutputPath::into_path);
    let ticket_out = ticket_output.map(OutputPath::into_path);
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
    let poller = if allow_non_public_egress {
        Poller::with_egress_policy(EgressPolicy::AllowNonPublic)
    } else {
        Poller::new()
    };
    let (report, wave_plan, execution_report, ticket_report): (
        BridgeReport,
        Option<WavePlan>,
        Option<WaveExecutionReport>,
        Option<TicketOperationReport>,
    ) = if let Some(state_path) = state {
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
        let mut ticket_report = None;
        let wave_plan = if let Some(path) = wave_out.as_ref() {
            if (execute_wave_mode || ticket_mint_root.is_some()) && path.exists() {
                let plan: WavePlan = strict_json::from_path(path, MAX_REGISTRY_BYTES)?;
                verify_wave_plan(&plan)?;
                Some(plan)
            } else {
                let plan = plan_wave(
                    &ledger,
                    &wave_target,
                    now,
                    wave_max_jobs,
                    wave_max_per_source,
                )?;
                if (execute_wave_mode || ticket_mint_root.is_some())
                    && plan.ledger_hash != ledger_digest(&ledger)
                {
                    return Err("fresh plan does not bind the current ledger".into());
                }
                Some(plan)
            }
        } else {
            None
        };
        // In execution mode the immutable plan is the recovery anchor. Persist it
        // before outcomes can consume pending jobs; otherwise a plan-write failure
        // after state commit would make the original wave unrecoverable.
        if execute_wave_mode
            || (ticket_mint_root.is_some() && !wave_out.as_ref().is_some_and(|path| path.exists()))
        {
            if let (Some(path), Some(plan)) = (wave_out.as_ref(), wave_plan.as_ref()) {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(path, serde_json::to_string_pretty(plan)? + "\n")?;
            }
        }
        let execution_report = if execute_wave_mode {
            let plan = wave_plan.as_ref().expect("execution requires a plan");
            if ticketed_execution {
                let outcome = execute_ticketed_wave(
                    &mut ledger,
                    plan,
                    ticket_agent.as_deref().expect("ticket agent was validated"),
                    now,
                )?;
                ticket_report = Some(TicketOperationReport::new(
                    "execute",
                    outcome.transaction,
                    outcome.replayed,
                    ledger.tickets(),
                ));
                Some(outcome.execution)
            } else {
                Some(execute_wave(&mut ledger, plan, now)?)
            }
        } else {
            None
        };
        if let Some(nonce) = ticket_mint_root.as_deref() {
            let transaction = mint_wave_tickets(
                &mut ledger,
                wave_plan.as_ref().expect("mint requires a plan"),
                nonce,
                ticket_controller
                    .as_deref()
                    .expect("ticket controller was validated"),
                ticket_agent.as_deref().expect("ticket agent was validated"),
                now,
            )?;
            ticket_report = Some(TicketOperationReport::new(
                "mint",
                Some(transaction),
                false,
                ledger.tickets(),
            ));
        }
        if let Some(ticket_id) = ticket_transfer.as_deref() {
            let transaction = ledger.tickets_mut().transfer(
                ticket_id,
                ticket_agent.as_deref().expect("ticket agent was validated"),
                ticket_to
                    .as_deref()
                    .expect("ticket recipient was validated"),
                now,
            )?;
            ticket_report = Some(TicketOperationReport::new(
                "transfer",
                Some(transaction),
                false,
                ledger.tickets(),
            ));
        }
        if let Some(root_id) = ticket_revoke_root.as_deref() {
            let transaction = ledger.tickets_mut().revoke(
                root_id,
                ticket_agent.as_deref().expect("ticket agent was validated"),
                now,
            )?;
            ticket_report = Some(TicketOperationReport::new(
                "revoke",
                Some(transaction),
                false,
                ledger.tickets(),
            ));
        }
        ingestion.pending = ledger.len();
        ingestion.tombstones = ledger.consumed_len();
        Poller::ensure_deadline(
            poll_deadline,
            "after ingestion, wave planning and execution",
        )?;
        ledger.save_atomic(&state_path)?;
        ingestion.state_saved = true;
        let mut report = BridgeReport::new(registry.network_name.clone(), now, records);
        report.ingestion = Some(ingestion);
        (report, wave_plan, execution_report, ticket_report)
    } else {
        let polls = poller.poll_registry_detailed_with_deadline(&registry, now, poll_deadline)?;
        let records = polls.into_iter().map(|result| result.record).collect();
        (
            BridgeReport::new(registry.network_name.clone(), now, records),
            None,
            None,
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
        if !execute_wave_mode && ticket_mint_root.is_none() {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(path, serde_json::to_string_pretty(&plan)? + "\n")?;
        }
        eprintln!(
            "wave_jobs={} wave_deferred={} plan_hash={}",
            plan.jobs.len(),
            plan.deferred,
            plan.plan_hash
        );
    }
    if let (Some(path), Some(execution)) = (execution_out, &execution_report) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(execution)? + "\n")?;
        eprintln!(
            "execution_succeeded={} execution_dead_lettered={} execution_skipped={} execution_hash={}",
            execution.summary.succeeded,
            execution.summary.dead_lettered,
            execution.summary.skipped_succeeded + execution.summary.skipped_dead_lettered,
            execution.execution_hash
        );
    }
    if let (Some(path), Some(ticket)) = (ticket_out, &ticket_report) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, serde_json::to_string_pretty(ticket)? + "\n")?;
        eprintln!(
            "ticket_operation={} ticket_count={} ticket_transactions={} ticket_ledger_hash={}",
            ticket.operation,
            ticket.ticket_count,
            ticket.transaction_count,
            ticket.ticket_ledger_hash
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
    let execution_failed = execution_report.as_ref().is_some_and(|execution| {
        execution.results.iter().any(|result| {
            matches!(
                result.status.as_str(),
                "dead_lettered" | "skipped_dead_lettered"
            )
        })
    });
    if fail_on_error && (report.summary.failed > 0 || ingestion_failed || execution_failed) {
        return Err("poll, ingestion, or execution verification failed".into());
    }
    Ok(())
}
