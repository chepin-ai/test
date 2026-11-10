use asfa_bridge_poller::{
    append_block, append_directives, ingest_outbox, strict_json, verified_directives, ChainError,
    Directive, DirectiveLedger, IngestOutcome, Outbox, PollStatus, Poller, Registry, Session,
    TrustMode,
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
    assert!(ledger.consume("node", "once").is_some());
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
        json!("asfa-directive-ledger/v3")
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
        Err(ChainError::Rollback {
            stored: 2,
            presented: 0,
            ..
        })
    ));
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.checkpoint("node").unwrap().latest, second_head);

    let mut fork = Outbox::genesis("node", "file:///unused");
    append_directives(&mut fork, vec![item("fork-one")], 100, 0).unwrap();
    assert_ne!(fork.hash_chain.latest, first_head);
    append_directives(&mut fork, vec![item("fork-two")], 101, 0).unwrap();
    assert!(matches!(
        ingest_outbox(&mut restored, &fork, 103),
        Err(ChainError::Fork { height: 2, .. })
    ));
    assert_eq!(restored.len(), 2);
    assert_eq!(restored.consumed_len(), 0);
    assert_eq!(restored.checkpoint("node").unwrap().latest, second_head);

    append_directives(&mut fork, vec![item("fork-three")], 102, 0).unwrap();
    assert!(matches!(
        ingest_outbox(&mut restored, &fork, 103),
        Err(ChainError::Fork { height: 2, .. })
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
        json!("asfa-directive-ledger/v3")
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
