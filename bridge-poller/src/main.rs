use asfa_bridge_poller::{Poller, Registry};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn usage() {
    println!("asfa-bridge-poller --config <sessions.json> [--out report.json] [--now EPOCH] [--fail-on-error]");
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
    let mut now = now_epoch();
    let mut fail_on_error = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = args.next().ok_or("--config requires a path")?.into(),
            "--out" => out = Some(args.next().ok_or("--out requires a path")?.into()),
            "--now" => now = args.next().ok_or("--now requires epoch seconds")?.parse()?,
            "--fail-on-error" => fail_on_error = true,
            "--help" | "-h" => {
                usage();
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }

    let registry: Registry = serde_json::from_str(&fs::read_to_string(&config)?)?;
    let report = Poller::new().poll_registry(&registry, now);
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
    if fail_on_error && report.summary.failed > 0 {
        return Err(format!("{} session(s) failed verification", report.summary.failed).into());
    }
    Ok(())
}
