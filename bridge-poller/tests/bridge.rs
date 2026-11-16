use asfa_bridge_poller::{
    append_block, append_directives, execute_wave, ingest_outbox, strict_json, verified_directives,
    CapacityError, ChainError, Directive, DirectiveLedger, IngestError, IngestOutcome,
    LedgerSnapshot, Outbox, PollStatus, Poller, Registry, ResourceLimits, Session, TrustMode,
    WaveExecutionReport, WavePlan,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

fn session(url: String) -> Session {
    Session {
        url,
        canonical_url: None,
        role: Some("test".into()),
        trust: TrustMode::UnsignedHashChain,
        note: None,
        allow_insecure_http: true,
        allow_file: true,
    }
}

fn unused_path(label: &str) -> PathBuf {
    let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "asfa-bridge-test-{}-{label}-{id}.json",
        std::process::id()
    ))
}

fn temp_file(contents: &str) -> PathBuf {
    let path = unused_path("document");
    fs::write(&path, contents).unwrap();
    path
}

fn outbox_file(mut outbox: Outbox) -> (PathBuf, String) {
    let path = unused_path("outbox");
    let url = format!("file://{}", path.display());
    outbox.url = url.clone();
    fs::write(&path, serde_json::to_string(&outbox).unwrap()).unwrap();
    (path, url)
}

fn serve_once(status: &str, body: String) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let status = status.to_string();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request);
        let response = format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    format!("http://{address}")
}

fn serve_outbox_once(outbox: &mut Outbox) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}");
    outbox.url = url.clone();
    let body = serde_json::to_string(outbox).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    url
}

fn serve_counted_outbox_once(outbox: &mut Outbox) -> (String, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}");
    outbox.url = url.clone();
    let body = serde_json::to_string(outbox).unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let server_hits = Arc::clone(&hits);
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        server_hits.fetch_add(1, Ordering::SeqCst);
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request);
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    (url, hits)
}

fn serve_redirect_once(location: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let location = location.to_owned();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 2048];
        let _ = stream.read(&mut request);
        let response = format!(
            "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        );
        stream.write_all(response.as_bytes()).unwrap();
    });
    format!("http://{address}")
}

#[test]
fn file_transport_verifies_genesis_document() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (path, url) = outbox_file(outbox);
    let record = Poller::new().poll_session("node", &session(url), 100);
    assert_eq!(
        record.status,
        PollStatus::Verified {
            verified_blocks: 0,
            verified_directives: 0,
            untrusted_directives: 0
        }
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn malformed_json_is_an_observable_negative_result() {
    let path = temp_file("not-json");
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
    assert!(matches!(record.status, PollStatus::InvalidJson { .. }));
    fs::remove_file(path).unwrap();
}

#[test]
fn valid_json_with_wrong_schema_is_not_accepted() {
    let path = temp_file("{\"hello\":\"world\"}");
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
    assert!(matches!(record.status, PollStatus::InvalidSchema { .. }));
    fs::remove_file(path).unwrap();
}

#[test]
fn registry_and_document_session_must_match() {
    let outbox = Outbox::genesis("someone-else", "file:///unused");
    let (path, url) = outbox_file(outbox);
    let record = Poller::new().poll_session("node", &session(url), 100);
    assert!(matches!(record.status, PollStatus::InvalidSchema { .. }));
    fs::remove_file(path).unwrap();
}

#[test]
fn http_404_is_not_silently_skipped() {
    let url = serve_once("404 Not Found", "missing".into());
    let record = Poller::new().poll_session("node", &session(url), 100);
    assert_eq!(record.status, PollStatus::HttpStatus { code: 404 });
}

#[test]
fn http_transport_verifies_two_linked_blocks() {
    let mut outbox = Outbox::genesis("node", "http://unused");
    append_block(&mut outbox, json!({"sequence": 1}), 100, 0).unwrap();
    append_block(&mut outbox, json!({"sequence": 2}), 101, 0).unwrap();
    let url = serve_outbox_once(&mut outbox);
    let record = Poller::new().poll_session("node", &session(url), 102);
    assert_eq!(
        record.status,
        PollStatus::Verified {
            verified_blocks: 2,
            verified_directives: 0,
            untrusted_directives: 0
        }
    );
}

#[test]
fn tampered_http_payload_fails_chain_verification() {
    let mut outbox = Outbox::genesis("node", "http://unused");
    append_block(&mut outbox, json!({"sequence": 1}), 100, 0).unwrap();
    outbox.hash_chain.blocks[0].payload = json!({"sequence": 99});
    let url = serve_outbox_once(&mut outbox);
    let record = Poller::new().poll_session("node", &session(url), 102);
    assert!(matches!(record.status, PollStatus::InvalidTrust { .. }));
}

#[test]
fn hmac_is_explicitly_unsupported_not_treated_as_valid() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    outbox.trust = TrustMode::Hmac;
    let (path, url) = outbox_file(outbox);
    let record = Poller::new().poll_session("node", &session(url), 100);
    assert_eq!(
        record.status,
        PollStatus::UnsupportedTrust {
            mode: TrustMode::Hmac
        }
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn poll_reports_verified_and_legacy_directives_separately() {
    let mut outbox = Outbox::genesis("node", "http://unused");
    outbox.directives.push(Directive {
        id: "legacy".into(),
        from: "node".into(),
        to: "peer".into(),
        action: "Ping".into(),
        payload: json!({}),
        expires_epoch: None,
    });
    append_directives(
        &mut outbox,
        vec![Directive {
            id: "bound".into(),
            from: "node".into(),
            to: "peer".into(),
            action: "Ping".into(),
            payload: json!({}),
            expires_epoch: Some(200),
        }],
        100,
        0,
    )
    .unwrap();
    let url = serve_outbox_once(&mut outbox);
    let record = Poller::new().poll_session("node", &session(url), 102);
    assert_eq!(
        record.status,
        PollStatus::Verified {
            verified_blocks: 1,
            verified_directives: 1,
            untrusted_directives: 1
        }
    );
}

#[test]
fn oversized_document_is_rejected() {
    let path = temp_file(&"x".repeat(2 * 1024 * 1024 + 1));
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
    assert!(matches!(record.status, PollStatus::Transport { .. }));
    fs::remove_file(path).unwrap();
}

#[test]
fn session_trust_is_enforced_before_transport() {
    let mut config = session("file:///definitely-not-present.json".into());
    config.trust = TrustMode::Hmac;
    let record = Poller::new().poll_session("node", &config, 100);
    assert_eq!(
        record.status,
        PollStatus::UnsupportedTrust {
            mode: TrustMode::Hmac
        }
    );
}

#[test]
fn registry_trust_model_is_enforced_for_every_session() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (path, url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "negative".into(),
        trust_model: "hmac".into(),
        sessions: BTreeMap::from([("node".into(), session(url))]),
    };
    let report = Poller::new().poll_registry(&registry, 100);
    assert_eq!(report.summary.failed, 1);
    assert!(matches!(
        report.records[0].status,
        PollStatus::InvalidTrust { .. }
    ));
    fs::remove_file(path).unwrap();
}

#[test]
fn forged_directive_source_is_an_observable_failure() {
    let mut outbox = Outbox::genesis("node", "http://unused");
    append_block(
        &mut outbox,
        json!({
            "kind": "directives",
            "directives": [{
                "id": "forged",
                "from": "someone-else",
                "to": "peer",
                "action": "Ping",
                "payload": {}
            }]
        }),
        100,
        0,
    )
    .unwrap();
    let url = serve_outbox_once(&mut outbox);
    let record = Poller::new().poll_session("node", &session(url), 102);
    assert!(matches!(record.status, PollStatus::InvalidTrust { .. }));
}

#[test]
fn verified_directive_cannot_reenter_ledger_after_consumption() {
    let mut outbox = Outbox::genesis("node", "http://unused");
    append_directives(
        &mut outbox,
        vec![Directive {
            id: "once".into(),
            from: "node".into(),
            to: "peer".into(),
            action: "Ping".into(),
            payload: json!({"sequence": 1}),
            expires_epoch: Some(200),
        }],
        100,
        0,
    )
    .unwrap();
    let url = serve_outbox_once(&mut outbox);
    let record = Poller::new().poll_session("node", &session(url), 102);
    assert!(record.status.is_verified());

    let verified = verified_directives(&outbox).unwrap();
    let mut ledger = DirectiveLedger::new();
    assert_eq!(
        ledger.ingest("node", verified[0].clone(), 102),
        IngestOutcome::Inserted
    );
    assert!(ledger.consume("node", "once").unwrap().is_some());
    let mut restored = DirectiveLedger::from_snapshot(ledger.snapshot()).unwrap();
    assert_eq!(
        restored.ingest("node", verified[0].clone(), 102),
        IngestOutcome::Consumed
    );
    assert!(restored.pending_for_at("peer", 102).is_empty());
}

#[test]
fn cli_state_survives_independent_processes_and_blocks_replay() {
    let item = Directive {
        id: "once".into(),
        from: "node".into(),
        to: "peer".into(),
        action: "Ping".into(),
        payload: json!({"sequence": 1}),
        expires_epoch: Some(200),
    };
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(&mut outbox, vec![item.clone()], 100, 0).unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "cli-restart".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url.clone()))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("state");
    let first_report = unused_path("first-report");
    let second_report = unused_path("second-report");
    let third_report = unused_path("third-report");

    let run = |now: &str, consume: bool, report: &PathBuf| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"));
        command
            .arg("--config")
            .arg(&config)
            .arg("--state")
            .arg(&state)
            .arg("--out")
            .arg(report)
            .arg("--now")
            .arg(now);
        if consume {
            command
                .arg("--consume-session")
                .arg("node")
                .arg("--consume-id")
                .arg("once");
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&fs::read(report).unwrap()).unwrap()
    };

    let first = run("101", false, &first_report);
    assert_eq!(first["ingestion"]["inserted"], json!(1));
    assert_eq!(first["ingestion"]["pending"], json!(1));
    assert_eq!(first["ingestion"]["state_saved"], json!(true));

    let second = run("102", true, &second_report);
    assert_eq!(second["ingestion"]["duplicate"], json!(1));
    assert_eq!(second["ingestion"]["consume_result"], json!("consumed"));
    assert_eq!(second["ingestion"]["pending"], json!(0));
    assert_eq!(second["ingestion"]["tombstones"], json!(1));

    let third = run("103", false, &third_report);
    assert_eq!(third["ingestion"]["replayed_consumed"], json!(1));
    assert_eq!(third["ingestion"]["pending"], json!(0));
    assert_eq!(
        third["ingestion"]["events"][0]["outcome"],
        json!("consumed")
    );

    let mut restored = DirectiveLedger::load(&state).unwrap();
    assert_eq!(restored.ingest("node", item, 103), IngestOutcome::Consumed);
    for path in [
        outbox_path,
        config,
        state,
        first_report,
        second_report,
        third_report,
    ] {
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn cli_invalid_state_fails_without_overwriting_it() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "cli-invalid-state".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url.clone()))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = temp_file("not-json");
    let report = unused_path("invalid-state-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--config")
        .arg(&config)
        .arg("--state")
        .arg(&state)
        .arg("--out")
        .arg(&report)
        .arg("--now")
        .arg("100")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&state).unwrap(), "not-json");
    assert!(!report.exists());
    fs::remove_file(outbox_path).unwrap();
    fs::remove_file(config).unwrap();
    fs::remove_file(state).unwrap();
}

#[test]
fn ingest_outbox_does_not_partially_apply_a_later_forged_block() {
    let valid = Directive {
        id: "valid".into(),
        from: "node".into(),
        to: "peer".into(),
        action: "Ping".into(),
        payload: json!({}),
        expires_epoch: None,
    };
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(&mut outbox, vec![valid], 100, 0).unwrap();
    append_block(
        &mut outbox,
        json!({
            "kind": "directives",
            "directives": [{
                "id": "forged",
                "from": "other",
                "to": "peer",
                "action": "Ping",
                "payload": {}
            }]
        }),
        101,
        0,
    )
    .unwrap();
    let mut ledger = DirectiveLedger::new();
    assert!(ingest_outbox(&mut ledger, &outbox, 102).is_err());
    assert!(ledger.is_empty());
    assert_eq!(ledger.consumed_len(), 0);
    assert_eq!(ledger.checkpoint_len(), 0);
}

#[test]
fn python_generated_non_ascii_chain_verifies_in_rust() {
    let path = temp_file(include_str!("../../fixtures/python-oracle-outbox.json"));
    let mut mirror = session(format!("file://{}", path.display()));
    mirror.canonical_url = Some("file://fixtures/python-oracle-outbox.json".into());
    let record = Poller::new().poll_session("oracle", &mirror, 100);
    assert_eq!(
        record.status,
        PollStatus::Verified {
            verified_blocks: 1,
            verified_directives: 1,
            untrusted_directives: 0,
        }
    );
    fs::remove_file(path).unwrap();
}

#[test]
fn duplicate_json_members_are_rejected_before_schema_or_chain_processing() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let rendered = serde_json::to_string(&outbox).unwrap();
    let duplicate_session = rendered.replacen(
        "\"session\":\"node\"",
        "\"session\":\"other\",\"session\":\"node\"",
        1,
    );
    let path = temp_file(&duplicate_session);
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
    assert!(matches!(
        record.status,
        PollStatus::InvalidJson { message } if message.contains("duplicate JSON object member")
    ));
    fs::remove_file(path).unwrap();

    let mut with_directive = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut with_directive,
        vec![Directive {
            id: "one".into(),
            from: "node".into(),
            to: "peer".into(),
            action: "Ping".into(),
            payload: json!({}),
            expires_epoch: None,
        }],
        100,
        0,
    )
    .unwrap();
    let rendered = serde_json::to_string(&with_directive).unwrap();
    let duplicate_nested_action = rendered.replacen(
        "\"action\":\"Ping\"",
        "\"action\":\"Harm\",\"action\":\"Ping\"",
        1,
    );
    assert_ne!(rendered, duplicate_nested_action);
    let path = temp_file(&duplicate_nested_action);
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
    assert!(matches!(
        record.status,
        PollStatus::InvalidJson { message } if message.contains("duplicate JSON object member")
    ));
    fs::remove_file(path).unwrap();
}

#[test]
fn cli_duplicate_registry_member_does_not_create_state() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url.clone()))]),
    };
    let rendered = serde_json::to_string(&registry).unwrap();
    let polluted = rendered.replacen(
        "\"network_name\":\"alpha\"",
        "\"network_name\":\"beta\",\"network_name\":\"alpha\"",
        1,
    );
    let config = temp_file(&polluted);
    let state = unused_path("duplicate-registry-state");
    let report = unused_path("duplicate-registry-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--config")
        .arg(&config)
        .arg("--state")
        .arg(&state)
        .arg("--out")
        .arg(&report)
        .arg("--now")
        .arg("100")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!state.exists());
    assert!(!report.exists());
    fs::remove_file(outbox_path).unwrap();
    fs::remove_file(config).unwrap();
}

#[test]
fn cli_cross_network_state_reuse_fails_without_overwrite() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![Directive {
            id: "shared-id".into(),
            from: "node".into(),
            to: "peer".into(),
            action: "Ping".into(),
            payload: json!({}),
            expires_epoch: None,
        }],
        100,
        0,
    )
    .unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry_for = |network: &str| Registry {
        schema_version: "test".into(),
        network_name: network.into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url.clone()))]),
    };
    let alpha_config = temp_file(&serde_json::to_string(&registry_for("alpha")).unwrap());
    let beta_config = temp_file(&serde_json::to_string(&registry_for("beta")).unwrap());
    let state = unused_path("network-state");
    let alpha_report = unused_path("alpha-report");
    let beta_report = unused_path("beta-report");

    let first = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--config")
        .arg(&alpha_config)
        .arg("--state")
        .arg(&state)
        .arg("--out")
        .arg(&alpha_report)
        .arg("--now")
        .arg("101")
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "alpha CLI failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let before = fs::read(&state).unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(
        snapshot["schema_version"],
        json!("asfa-directive-ledger/v4")
    );
    assert_eq!(snapshot["network_name"], json!("alpha"));

    let second = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--config")
        .arg(&beta_config)
        .arg("--state")
        .arg(&state)
        .arg("--out")
        .arg(&beta_report)
        .arg("--now")
        .arg("101")
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("ledger network mismatch"));
    assert_eq!(fs::read(&state).unwrap(), before);
    assert!(!beta_report.exists());
    assert!(DirectiveLedger::load_for_registry(&state, &registry_for("alpha")).is_ok());
    assert!(DirectiveLedger::load_for_registry(&state, &registry_for("beta")).is_err());

    for path in [outbox_path, alpha_config, beta_config, state, alpha_report] {
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn checkpoints_accept_extension_and_reject_rollback_and_forks_without_mutation() {
    let item = |id: &str| Directive {
        id: id.into(),
        from: "node".into(),
        to: "peer".into(),
        action: "Ping".into(),
        payload: json!({"id": id}),
        expires_epoch: None,
    };
    let mut original = Outbox::genesis("node", "file:///unused");
    append_directives(&mut original, vec![item("one")], 100, 0).unwrap();
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "checkpoint-test".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(original.url.clone()))]),
    };
    let mut ledger = DirectiveLedger::for_registry(&registry);
    let first = ingest_outbox(&mut ledger, &original, 101).unwrap();
    assert_eq!(first.inserted, 1);
    assert_eq!(first.chain_checkpoints, 1);
    let first_head = original.hash_chain.latest.clone();

    append_directives(&mut original, vec![item("two")], 101, 0).unwrap();
    let extended = ingest_outbox(&mut ledger, &original, 102).unwrap();
    assert_eq!(extended.inserted, 1);
    assert_eq!(extended.duplicate, 1);
    assert_eq!(ledger.len(), 2);
    assert_eq!(ledger.checkpoint("node").unwrap().height, 2);
    let second_head = original.hash_chain.latest.clone();

    let checkpoint_state = unused_path("checkpoint-state");
    ledger.save_atomic(&checkpoint_state).unwrap();
    let mut restored = DirectiveLedger::load_for_registry(&checkpoint_state, &registry).unwrap();
    assert_eq!(restored.checkpoint("node").unwrap().latest, second_head);
    let genesis = Outbox::genesis("node", "file:///unused");
    assert!(matches!(
        ingest_outbox(&mut restored, &genesis, 103),
        Err(IngestError::Chain(ChainError::Rollback {
            stored: 2,
            presented: 0,
            ..
        }))
    ));
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.checkpoint("node").unwrap().latest, second_head);

    let mut fork = Outbox::genesis("node", "file:///unused");
    append_directives(&mut fork, vec![item("fork-one")], 100, 0).unwrap();
    assert_ne!(fork.hash_chain.latest, first_head);
    append_directives(&mut fork, vec![item("fork-two")], 101, 0).unwrap();
    assert!(matches!(
        ingest_outbox(&mut restored, &fork, 103),
        Err(IngestError::Chain(ChainError::Fork { height: 2, .. }))
    ));
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.consumed_len(), 0);
    assert_eq!(restored.checkpoint("node").unwrap().latest, second_head);

    append_directives(&mut fork, vec![item("fork-three")], 102, 0).unwrap();
    assert!(matches!(
        ingest_outbox(&mut restored, &fork, 103),
        Err(IngestError::Chain(ChainError::Fork { height: 2, .. }))
    ));
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.checkpoint("node").unwrap().height, 2);
    assert_eq!(restored.checkpoint("node").unwrap().latest, second_head);

    let reread = ingest_outbox(&mut restored, &original, 104).unwrap();
    assert_eq!(reread.duplicate, 2);
    assert_eq!(restored.len(), 2);
    fs::remove_file(checkpoint_state).unwrap();
}

#[test]
fn redirects_are_explicit_failures_and_never_reach_the_second_hop() {
    let mut target = Outbox::genesis("node", "http://unused");
    let (target_url, target_hits) = serve_counted_outbox_once(&mut target);
    let entry_url = serve_redirect_once(&target_url);
    let record = Poller::new().poll_session("node", &session(entry_url), 100);
    assert_eq!(record.status, PollStatus::HttpStatus { code: 302 });
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);
}

#[test]
fn outbox_url_must_match_the_declared_canonical_url() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (path, url) = outbox_file(outbox);
    let mut mirror = session(url);
    mirror.canonical_url = Some("https://canonical.example/outbox.json".into());
    let record = Poller::new().poll_session("node", &mirror, 100);
    assert!(matches!(
        record.status,
        PollStatus::InvalidTrust { message } if message.contains("canonical URL mismatch")
    ));
    fs::remove_file(path).unwrap();
}

#[test]
fn insecure_transports_require_explicit_opt_in_before_io() {
    let mut file = session("file:///definitely-not-present.json".into());
    file.allow_file = false;
    let record = Poller::new().poll_session("node", &file, 100);
    assert!(matches!(
        record.status,
        PollStatus::Transport { message } if message.contains("allow_file=true")
    ));

    let mut target = Outbox::genesis("node", "http://unused");
    let (target_url, target_hits) = serve_counted_outbox_once(&mut target);
    let mut http = session(target_url);
    http.allow_insecure_http = false;
    let record = Poller::new().poll_session("node", &http, 100);
    assert!(matches!(
        record.status,
        PollStatus::Transport { message } if message.contains("allow_insecure_http=true")
    ));
    assert_eq!(target_hits.load(Ordering::SeqCst), 0);

    let userinfo = session("https://user:password@example.com/outbox.json".into());
    let record = Poller::new().poll_session("node", &userinfo, 100);
    assert!(matches!(
        record.status,
        PollStatus::Transport { message } if message.contains("userinfo")
    ));
}

#[test]
fn unknown_protocol_fields_are_rejected_instead_of_silently_ignored() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (path, url) = outbox_file(outbox);
    let mut polluted: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    polluted
        .as_object_mut()
        .unwrap()
        .insert("trusted".into(), json!(true));
    fs::write(&path, serde_json::to_vec(&polluted).unwrap()).unwrap();
    let record = Poller::new().poll_session("node", &session(url.clone()), 100);
    assert!(matches!(
        record.status,
        PollStatus::InvalidSchema { message } if message.contains("unknown field")
    ));

    let registry = Registry {
        schema_version: "test".into(),
        network_name: "strict-fields".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(url))]),
    };
    let mut polluted_registry = serde_json::to_value(&registry).unwrap();
    polluted_registry
        .as_object_mut()
        .unwrap()
        .insert("verify".into(), json!(false));
    assert!(serde_json::from_value::<Registry>(polluted_registry).is_err());
    fs::remove_file(path).unwrap();
}

#[test]
fn policy_digest_binds_security_fields_and_excludes_descriptions() {
    let fetch_url = "https://mirror.example/outbox.json".to_owned();
    let registry = Registry {
        schema_version: "registry-v1".into(),
        network_name: "policy-test".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(fetch_url.clone()))]),
    };
    let expected = registry.policy_digest();

    let mut descriptive = registry.clone();
    descriptive.sessions.get_mut("node").unwrap().role = Some("changed-role".into());
    descriptive.sessions.get_mut("node").unwrap().note = Some("changed-note".into());
    assert_eq!(descriptive.policy_digest(), expected);

    let mut explicit_default = registry.clone();
    explicit_default
        .sessions
        .get_mut("node")
        .unwrap()
        .canonical_url = Some(fetch_url);
    assert_eq!(explicit_default.policy_digest(), expected);

    let mut changed_url = registry.clone();
    changed_url.sessions.get_mut("node").unwrap().url = "https://other.example/outbox.json".into();
    assert_ne!(changed_url.policy_digest(), expected);

    let mut changed_canonical = registry.clone();
    changed_canonical
        .sessions
        .get_mut("node")
        .unwrap()
        .canonical_url = Some("https://canonical.example/other.json".into());
    assert_ne!(changed_canonical.policy_digest(), expected);

    let mut changed_transport = registry.clone();
    changed_transport
        .sessions
        .get_mut("node")
        .unwrap()
        .allow_insecure_http = !registry.sessions["node"].allow_insecure_http;
    assert_ne!(changed_transport.policy_digest(), expected);

    let mut changed_trust = registry.clone();
    changed_trust.sessions.get_mut("node").unwrap().trust = TrustMode::Hmac;
    assert_ne!(changed_trust.policy_digest(), expected);

    let mut changed_network = registry.clone();
    changed_network.network_name = "other-network".into();
    assert_ne!(changed_network.policy_digest(), expected);
}

#[test]
fn cli_same_network_policy_change_preserves_state_but_description_change_is_compatible() {
    let item = Directive {
        id: "policy-bound".into(),
        from: "node".into(),
        to: "peer".into(),
        action: "Ping".into(),
        payload: json!({"sequence": 1}),
        expires_epoch: None,
    };
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(&mut outbox, vec![item], 100, 0).unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let alternate_path = unused_path("alternate-outbox");
    fs::copy(&outbox_path, &alternate_path).unwrap();
    let alternate_url = format!("file://{}", alternate_path.display());

    let registry_for = |url: String, descriptive: bool| {
        let mut node = session(url);
        if descriptive {
            node.role = Some("changed-description".into());
            node.note = Some("not a security policy change".into());
        }
        Registry {
            schema_version: "test".into(),
            network_name: "same-network".into(),
            trust_model: "unsigned-hash-chain".into(),
            sessions: BTreeMap::from([("node".into(), node)]),
        }
    };
    let first_registry = registry_for(outbox_url.clone(), false);
    let second_registry = registry_for(alternate_url, false);
    let third_registry = registry_for(outbox_url, true);
    let first_config = temp_file(&serde_json::to_string(&first_registry).unwrap());
    let second_config = temp_file(&serde_json::to_string(&second_registry).unwrap());
    let third_config = temp_file(&serde_json::to_string(&third_registry).unwrap());
    let state = unused_path("policy-state");
    let first_report = unused_path("policy-first-report");
    let second_report = unused_path("policy-second-report");
    let third_report = unused_path("policy-third-report");

    let run = |config: &PathBuf, report: &PathBuf| {
        Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
            .arg("--config")
            .arg(config)
            .arg("--state")
            .arg(&state)
            .arg("--out")
            .arg(report)
            .arg("--now")
            .arg("101")
            .output()
            .unwrap()
    };

    let first = run(&first_config, &first_report);
    assert!(
        first.status.success(),
        "first policy run failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&first_report).unwrap()).unwrap();
    assert_eq!(first_json["ingestion"]["inserted"], json!(1));
    let before = fs::read(&state).unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(
        snapshot["schema_version"],
        json!("asfa-directive-ledger/v4")
    );
    assert_eq!(
        snapshot["policy_hash"],
        json!(first_registry.policy_digest())
    );

    let second = run(&second_config, &second_report);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("ledger policy mismatch"));
    assert_eq!(fs::read(&state).unwrap(), before);
    assert!(!second_report.exists());

    let third = run(&third_config, &third_report);
    assert!(
        third.status.success(),
        "description-only change failed: {}",
        String::from_utf8_lossy(&third.stderr)
    );
    let third_json: serde_json::Value =
        serde_json::from_slice(&fs::read(&third_report).unwrap()).unwrap();
    assert_eq!(third_json["ingestion"]["duplicate"], json!(1));
    assert_eq!(third_json["ingestion"]["conflict"], json!(0));

    for path in [
        outbox_path,
        alternate_path,
        first_config,
        second_config,
        third_config,
        state,
        first_report,
        third_report,
    ] {
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn cli_v2_snapshot_is_not_implicitly_migrated() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "v2-test".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let v2 = json!({
        "schema_version": "asfa-directive-ledger/v2",
        "network_name": "v2-test",
        "directives": [],
        "consumed": [],
        "checkpoints": []
    });
    let state = temp_file(&serde_json::to_string(&v2).unwrap());
    let before = fs::read(&state).unwrap();
    let report = unused_path("v2-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--config")
        .arg(&config)
        .arg("--state")
        .arg(&state)
        .arg("--out")
        .arg(&report)
        .arg("--now")
        .arg("100")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported ledger schema"));
    assert_eq!(fs::read(&state).unwrap(), before);
    assert!(!report.exists());
    for path in [outbox_path, config, state] {
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn cli_oversized_registry_fails_before_state_or_report_creation() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "oversize-config".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let rendered = format!(
        "{}{}",
        " ".repeat(2 * 1024 * 1024 + 1),
        serde_json::to_string(&registry).unwrap()
    );
    let config = temp_file(&rendered);
    let state = unused_path("oversize-config-state");
    let report = unused_path("oversize-config-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--config")
        .arg(&config)
        .arg("--state")
        .arg(&state)
        .arg("--out")
        .arg(&report)
        .arg("--now")
        .arg("100")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("JSON input exceeds 2097152 bytes"));
    assert!(!state.exists());
    assert!(!report.exists());
    fs::remove_file(outbox_path).unwrap();
    fs::remove_file(config).unwrap();
}

#[test]
fn policy_digest_matches_independent_python_known_answer() {
    let fixture: serde_json::Value =
        strict_json::from_str(include_str!("../../fixtures/policy-oracle.json")).unwrap();
    let registry: Registry = serde_json::from_value(fixture["registry"].clone()).unwrap();
    assert_eq!(
        registry.policy_digest(),
        fixture["expected_policy_sha256"].as_str().unwrap()
    );
}

fn saturation_directive(session: &str, id: &str) -> Directive {
    Directive {
        id: id.into(),
        from: session.into(),
        to: "qfos".into(),
        action: "engine.ping".into(),
        payload: json!({"id": id}),
        expires_epoch: None,
    }
}

#[test]
fn capacity_failures_discard_the_entire_staged_batch() {
    let limits = ResourceLimits {
        max_pending_directives: 1,
        max_consumed_tombstones: 4,
        max_directives_per_outbox: 4,
    };
    let mut ledger = DirectiveLedger::new().with_limits(limits);
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![
            saturation_directive("node", "one"),
            saturation_directive("node", "two"),
        ],
        100,
        0,
    )
    .unwrap();
    assert!(matches!(
        ingest_outbox(&mut ledger, &outbox, 100),
        Err(IngestError::Capacity(CapacityError::PendingDirectives {
            limit: 1
        }))
    ));
    assert!(ledger.is_empty());
    assert!(ledger.checkpoint("node").is_none());

    let mut ledger = DirectiveLedger::new().with_limits(ResourceLimits {
        max_directives_per_outbox: 1,
        ..limits
    });
    assert!(matches!(
        ingest_outbox(&mut ledger, &outbox, 100),
        Err(IngestError::Capacity(CapacityError::DirectivesPerOutbox {
            limit: 1,
            actual: 2
        }))
    ));
    assert!(ledger.is_empty());
}

#[test]
fn cli_pending_capacity_does_not_create_state_or_report() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![
            saturation_directive("node", "one"),
            saturation_directive("node", "two"),
        ],
        100,
        0,
    )
    .unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("capacity-state");
    let report = unused_path("capacity-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--out", report.to_str().unwrap()])
        .args(["--now", "100", "--max-pending", "1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("pending directive capacity exceeded: limit=1"));
    assert!(!state.exists());
    assert!(!report.exists());
    let _ = fs::remove_file(format!("{}.lock", state.display()));
    fs::remove_file(outbox_path).unwrap();
    fs::remove_file(config).unwrap();
}

#[test]
fn cli_tombstone_capacity_preserves_state_and_pending_job() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![
            saturation_directive("node", "one"),
            saturation_directive("node", "two"),
        ],
        100,
        0,
    )
    .unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("tombstone-state");
    for id in ["one", "two"] {
        let before = if id == "two" {
            Some(fs::read(&state).unwrap())
        } else {
            None
        };
        let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
            .args(["--config", config.to_str().unwrap()])
            .args(["--state", state.to_str().unwrap()])
            .args(["--now", "100", "--max-tombstones", "1"])
            .args(["--consume-session", "node", "--consume-id", id])
            .output()
            .unwrap();
        if id == "one" {
            assert!(output.status.success());
        } else {
            assert!(!output.status.success());
            assert!(String::from_utf8_lossy(&output.stderr)
                .contains("consumed tombstone capacity exceeded: limit=1"));
            assert_eq!(fs::read(&state).unwrap(), before.unwrap());
        }
    }
    let snapshot: serde_json::Value =
        strict_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(snapshot["consumed"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["directives"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["directives"][0]["directive"]["id"], "two");
    fs::remove_file(outbox_path).unwrap();
    fs::remove_file(config).unwrap();
    fs::remove_file(&state).unwrap();
    let _ = fs::remove_file(format!("{}.lock", state.display()));
}

#[test]
fn cli_registry_fanout_fails_before_transport_or_outputs() {
    let mut document = Outbox::genesis("node-0", "file:///unused");
    let (url, hits) = serve_counted_outbox_once(&mut document);
    let sessions = (0..65)
        .map(|index| (format!("node-{index}"), session(url.clone())))
        .collect();
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions,
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("fanout-state");
    let report = unused_path("fanout-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--out", report.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("registry session capacity exceeded: limit=64, actual=65"));
    assert_eq!(hits.load(Ordering::SeqCst), 0);
    assert!(!state.exists());
    assert!(!report.exists());
    fs::remove_file(config).unwrap();
}

#[test]
fn cli_wave_plan_is_deterministic_fair_and_state_bound() {
    let mut sessions = BTreeMap::new();
    let mut paths = Vec::new();
    for name in ["a", "b"] {
        let mut outbox = Outbox::genesis(name, "file:///unused");
        append_directives(
            &mut outbox,
            vec![
                saturation_directive(name, &format!("{name}1")),
                saturation_directive(name, &format!("{name}2")),
            ],
            100,
            0,
        )
        .unwrap();
        let (path, url) = outbox_file(outbox);
        paths.push(path);
        sessions.insert(name.into(), session(url));
    }
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions,
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("wave-state");
    let wave = unused_path("wave-plan");
    for _ in 0..2 {
        let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
            .args(["--config", config.to_str().unwrap()])
            .args(["--state", state.to_str().unwrap()])
            .args(["--now", "100"])
            .args(["--wave-out", wave.to_str().unwrap()])
            .args(["--wave-max-jobs", "3", "--wave-max-per-source", "1"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let plan: serde_json::Value =
        strict_json::from_str(&fs::read_to_string(&wave).unwrap()).unwrap();
    assert_eq!(plan["schema_version"], "qfos-wave-plan/v1");
    assert_eq!(plan["mode"], "plan-only-no-execution");
    assert_eq!(plan["jobs"].as_array().unwrap().len(), 2);
    assert_eq!(plan["jobs"][0]["id"], "a1");
    assert_eq!(plan["jobs"][1]["id"], "b1");
    assert_eq!(plan["deferred"], 2);
    assert_eq!(plan["plan_hash"].as_str().unwrap().len(), 64);
    let snapshot: serde_json::Value =
        strict_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(snapshot["directives"].as_array().unwrap().len(), 4);
    assert!(snapshot["consumed"].as_array().unwrap().is_empty());
    for path in paths {
        fs::remove_file(path).unwrap();
    }
    fs::remove_file(config).unwrap();
    fs::remove_file(&state).unwrap();
    fs::remove_file(wave).unwrap();
    let _ = fs::remove_file(format!("{}.lock", state.display()));
}

#[test]
fn cli_capacity_flags_require_values_and_cannot_raise_hard_caps() {
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .arg("--max-pending")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--max-pending requires N"));
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--max-pending", "4097"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--max-pending must be in 1..=4096"));
}

fn nested_arrays(depth: usize) -> serde_json::Value {
    (0..depth).fold(json!(0), |value, _| json!([value]))
}

fn delayed_outbox_server(name: &str, delay: Duration) -> (String, Arc<AtomicU64>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}");
    let body = serde_json::to_string(&Outbox::genesis(name, &url)).unwrap();
    let hits = Arc::new(AtomicU64::new(0));
    let server_hits = Arc::clone(&hits);
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            server_hits.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request);
            std::thread::sleep(delay);
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    (url, hits)
}

#[test]
fn whole_poll_deadline_shrinks_the_active_request() {
    let (url, _hits) = delayed_outbox_server("a", Duration::from_secs(1));
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "deadline-unit".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("a".into(), session(url))]),
    };
    let started = Instant::now();
    let error = Poller::new()
        .poll_registry_detailed_with_deadline(
            &registry,
            100,
            Instant::now() + Duration::from_millis(40),
        )
        .unwrap_err();
    assert!(error.to_string().contains("whole-poll deadline exceeded"));
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "request did not shrink to the remaining budget: {:?}",
        started.elapsed()
    );
}

#[test]
fn cli_whole_poll_deadline_prevents_later_transport_and_report() {
    let (first_url, first_hits) = delayed_outbox_server("a", Duration::from_millis(500));
    let (second_url, second_hits) = {
        let mut outbox = Outbox::genesis("b", "http://unused");
        serve_counted_outbox_once(&mut outbox)
    };
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "deadline-cli".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([
            ("a".into(), session(first_url)),
            ("b".into(), session(second_url)),
        ]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let report = unused_path("deadline-report");
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--out", report.to_str().unwrap()])
        .args(["--poll-timeout-ms", "40"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("whole-poll deadline exceeded"));
    assert_eq!(first_hits.load(Ordering::SeqCst), 1);
    assert_eq!(second_hits.load(Ordering::SeqCst), 0);
    assert!(!report.exists());
    fs::remove_file(config).unwrap();
}

#[test]
fn cli_json_depth_and_node_budgets_reject_open_outbox_payloads() {
    for (label, mailbox, expected) in [
        ("depth", nested_arrays(64), "JSON depth budget exceeded"),
        (
            "nodes",
            serde_json::Value::Array((0..16_384).map(|_| json!(0)).collect()),
            "JSON node budget exceeded",
        ),
    ] {
        let mut outbox = Outbox::genesis("node", "file:///unused");
        outbox.mailbox = mailbox;
        let (outbox_path, outbox_url) = outbox_file(outbox);
        let registry = Registry {
            schema_version: "test".into(),
            network_name: format!("json-budget-{label}"),
            trust_model: "unsigned-hash-chain".into(),
            sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
        };
        let config = temp_file(&serde_json::to_string(&registry).unwrap());
        let report = unused_path("json-budget-report");
        let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
            .args(["--config", config.to_str().unwrap()])
            .args(["--out", report.to_str().unwrap()])
            .arg("--fail-on-error")
            .output()
            .unwrap();
        assert!(!output.status.success());
        let report: serde_json::Value =
            serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
        let message = report["records"][0]["status"]["message"].as_str().unwrap();
        assert!(message.contains(expected), "{message}");
        assert_eq!(report["records"][0]["status"]["kind"], "invalid_json");
        fs::remove_file(config).unwrap();
        fs::remove_file(outbox_path).unwrap();
    }
}

#[test]
fn cli_json_budget_also_covers_registry_and_snapshot_restore() {
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "json-registry".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::new(),
    };
    let mut registry_value = serde_json::to_value(&registry).unwrap();
    registry_value["extension"] = nested_arrays(64);
    let config = temp_file(&registry_value.to_string());
    let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("JSON depth budget exceeded"));

    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![Directive {
            id: "snapshot".into(),
            from: "node".into(),
            to: "peer".into(),
            action: "Ping".into(),
            payload: json!({}),
            expires_epoch: None,
        }],
        100,
        0,
    )
    .unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "json-snapshot".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let snapshot_config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("json-snapshot-state");
    let first = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", snapshot_config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(first.status.success());
    let mut snapshot: serde_json::Value =
        serde_json::from_slice(&fs::read(&state).unwrap()).unwrap();
    snapshot["directives"][0]["directive"]["payload"]["deep"] = nested_arrays(64);
    fs::write(&state, snapshot.to_string()).unwrap();
    let before = fs::read(&state).unwrap();
    let second = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", snapshot_config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("JSON depth budget exceeded"));
    assert_eq!(fs::read(&state).unwrap(), before);
    for path in [config, outbox_path, snapshot_config, state] {
        fs::remove_file(path).unwrap();
    }
}

#[test]
fn cli_poll_timeout_flag_requires_a_bounded_value() {
    for args in [
        vec!["--poll-timeout-ms"],
        vec!["--poll-timeout-ms", "0"],
        vec!["--poll-timeout-ms", "60001"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
    }
}

fn executable_directive(
    id: &str,
    action: &str,
    payload: serde_json::Value,
    expires: Option<u64>,
) -> Directive {
    Directive {
        id: id.into(),
        from: "node".into(),
        to: "qfos".into(),
        action: action.into(),
        payload,
        expires_epoch: expires,
    }
}

#[test]
fn cli_execution_dead_letters_and_report_failure_resume_without_reexecution() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![
            executable_directive("sum", "engine.sum", json!({"values": [20, 22]}), None),
            executable_directive("sha", "engine.sha256", json!({"text": "abc"}), None),
            executable_directive("unknown", "engine.shell", json!({"command": "true"}), None),
            executable_directive("invalid", "engine.sum", json!({"values": null}), None),
            executable_directive(
                "overflow",
                "engine.sum",
                json!({"values": [i64::MAX, 1]}),
                None,
            ),
            executable_directive("expired", "engine.sum", json!({"values": [1]}), Some(99)),
        ],
        1,
        0,
    )
    .unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "exec-alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("execution-state");
    let wave = unused_path("execution-wave");
    let execution = unused_path("execution-report");
    let replay_execution = unused_path("execution-replay-report");
    let bad_execution = unused_path("execution-report-directory");
    fs::create_dir(&bad_execution).unwrap();

    let planned = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--wave-out", wave.to_str().unwrap(), "--now", "50"])
        .output()
        .unwrap();
    assert!(
        planned.status.success(),
        "{}",
        String::from_utf8_lossy(&planned.stderr)
    );

    let failed_output = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--wave-out", wave.to_str().unwrap()])
        .args([
            "--execute-wave",
            "--execution-out",
            bad_execution.to_str().unwrap(),
        ])
        .args(["--now", "100"])
        .output()
        .unwrap();
    assert!(!failed_output.status.success());
    assert!(state.exists());
    let committed = fs::read(&state).unwrap();
    let snapshot: serde_json::Value = serde_json::from_slice(&committed).unwrap();
    assert_eq!(snapshot["schema_version"], "asfa-directive-ledger/v4");
    assert_eq!(snapshot["directives"].as_array().unwrap().len(), 0);
    assert_eq!(snapshot["consumed"].as_array().unwrap().len(), 6);
    assert_eq!(snapshot["receipts"].as_array().unwrap().len(), 2);
    assert_eq!(snapshot["dead_letters"].as_array().unwrap().len(), 4);

    let resumed = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--wave-out", wave.to_str().unwrap()])
        .args([
            "--execute-wave",
            "--execution-out",
            execution.to_str().unwrap(),
        ])
        .args(["--now", "100"])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "{}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    assert_eq!(fs::read(&state).unwrap(), committed);
    let report: serde_json::Value =
        strict_json::from_str(&fs::read_to_string(&execution).unwrap()).unwrap();
    assert_eq!(report["profile"], "qfos-exec-v1");
    assert_eq!(report["summary"]["offered"], 6);
    assert_eq!(report["summary"]["succeeded"], 0);
    assert_eq!(report["summary"]["dead_lettered"], 0);
    assert_eq!(report["summary"]["skipped_succeeded"], 2);
    assert_eq!(report["summary"]["skipped_dead_lettered"], 4);
    let results = report["results"].as_array().unwrap();
    let sum = results
        .iter()
        .find(|result| result["id"] == "sum")
        .and_then(|result| result["receipt"].as_object())
        .unwrap();
    assert_eq!(sum["output"], json!({"count": 2, "sum": 42}));
    let sha = results
        .iter()
        .find(|result| result["id"] == "sha")
        .and_then(|result| result["receipt"].as_object())
        .unwrap();
    assert_eq!(
        sha["output"]["sha256"],
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let replayed = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--wave-out", wave.to_str().unwrap()])
        .args([
            "--execute-wave",
            "--execution-out",
            replay_execution.to_str().unwrap(),
        ])
        .args(["--now", "100"])
        .output()
        .unwrap();
    assert!(
        replayed.status.success(),
        "{}",
        String::from_utf8_lossy(&replayed.stderr)
    );
    assert_eq!(fs::read(&state).unwrap(), committed);
    assert_eq!(
        fs::read(&execution).unwrap(),
        fs::read(&replay_execution).unwrap()
    );

    let mut tampered_snapshot = snapshot.clone();
    tampered_snapshot["receipts"][0]["output"]["sum"] = json!(-1);
    let tampered = temp_file(&tampered_snapshot.to_string());
    assert!(DirectiveLedger::load(&tampered).is_err());

    for path in [
        outbox_path,
        config,
        wave,
        execution,
        replay_execution,
        tampered,
    ] {
        fs::remove_file(path).unwrap();
    }
    fs::remove_file(&state).unwrap();
    fs::remove_dir(bad_execution).unwrap();
    let _ = fs::remove_file(format!("{}.lock", state.display()));
}

#[test]
fn cli_fresh_execution_persists_recovery_plan_before_report_output() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    append_directives(
        &mut outbox,
        vec![executable_directive(
            "sum",
            "engine.sum",
            json!({"values": [40, 2]}),
            None,
        )],
        1,
        0,
    )
    .unwrap();
    let (outbox_path, outbox_url) = outbox_file(outbox);
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "exec-fresh".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([("node".into(), session(outbox_url))]),
    };
    let config = temp_file(&serde_json::to_string(&registry).unwrap());
    let state = unused_path("fresh-execution-state");
    let wave = unused_path("fresh-execution-wave");
    let bad_execution = unused_path("fresh-execution-directory");
    let execution = unused_path("fresh-execution-report");
    fs::create_dir(&bad_execution).unwrap();

    let first = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--wave-out", wave.to_str().unwrap()])
        .args([
            "--execute-wave",
            "--execution-out",
            bad_execution.to_str().unwrap(),
        ])
        .args(["--now", "100"])
        .output()
        .unwrap();
    assert!(!first.status.success());
    assert!(
        wave.exists(),
        "recovery plan must survive report output failure"
    );
    let snapshot: serde_json::Value =
        strict_json::from_str(&fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(snapshot["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(snapshot["receipts"][0]["output"]["sum"], 42);

    let recovered = Command::new(env!("CARGO_BIN_EXE_asfa-bridge-poller"))
        .args(["--config", config.to_str().unwrap()])
        .args(["--state", state.to_str().unwrap()])
        .args(["--wave-out", wave.to_str().unwrap()])
        .args([
            "--execute-wave",
            "--execution-out",
            execution.to_str().unwrap(),
        ])
        .args(["--now", "100"])
        .output()
        .unwrap();
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let report: serde_json::Value =
        strict_json::from_str(&fs::read_to_string(&execution).unwrap()).unwrap();
    assert_eq!(report["summary"]["succeeded"], 0);
    assert_eq!(report["summary"]["skipped_succeeded"], 1);

    for path in [outbox_path, config, wave, execution] {
        fs::remove_file(path).unwrap();
    }
    fs::remove_file(&state).unwrap();
    fs::remove_dir(bad_execution).unwrap();
    let _ = fs::remove_file(format!("{}.lock", state.display()));
}

#[test]
fn v3_snapshot_is_rejected_without_implicit_migration_or_file_mutation() {
    let snapshot = json!({
        "schema_version": "asfa-directive-ledger/v3",
        "network_name": null,
        "policy_hash": null,
        "directives": [],
        "consumed": [],
        "checkpoints": [],
        "receipts": [],
        "dead_letters": []
    });
    let path = temp_file(&snapshot.to_string());
    let before = fs::read(&path).unwrap();
    let error = DirectiveLedger::load(&path).unwrap_err();
    assert!(error.to_string().contains("unsupported ledger schema"));
    assert!(error.to_string().contains("refusing implicit migration"));
    assert_eq!(fs::read(&path).unwrap(), before);
    fs::remove_file(path).unwrap();
}

#[test]
fn execution_fixture_replays_exact_known_answers() {
    let registry: Registry =
        strict_json::from_str(include_str!("../../config/sessions.execution.json")).unwrap();
    let pre: LedgerSnapshot =
        strict_json::from_str(include_str!("../../fixtures/qfos-exec-pre-state.json")).unwrap();
    let expected_snapshot: LedgerSnapshot =
        strict_json::from_str(include_str!("../../fixtures/qfos-exec-state.json")).unwrap();
    let plan: WavePlan =
        strict_json::from_str(include_str!("../../fixtures/qfos-exec-plan.json")).unwrap();
    let expected_report: WaveExecutionReport =
        strict_json::from_str(include_str!("../../fixtures/qfos-exec-report.json")).unwrap();
    assert_eq!(
        pre.network_name.as_deref(),
        Some(registry.network_name.as_str())
    );
    let mut ledger = DirectiveLedger::from_snapshot(pre).unwrap();
    let actual = execute_wave(&mut ledger, &plan, 100).unwrap();
    assert_eq!(actual, expected_report);
    assert_eq!(ledger.snapshot(), expected_snapshot);
    assert_eq!(
        plan.plan_hash,
        "f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a"
    );
    assert_eq!(
        actual.execution_hash,
        "4cefca364f55ef97a41aeb580ab01b6c16c7a754a02acc78b23e14fc6da5a78c"
    );
}
