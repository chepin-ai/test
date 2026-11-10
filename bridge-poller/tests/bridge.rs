use asfa_bridge_poller::{
    append_block, append_directives, ingest_outbox, verified_directives, ChainError, Directive,
    DirectiveLedger, IngestOutcome, Outbox, PollStatus, Poller, Registry, Session, TrustMode,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_FILE: AtomicU64 = AtomicU64::new(1);

fn session(url: String) -> Session {
    Session {
        url,
        role: Some("test".into()),
        trust: TrustMode::UnsignedHashChain,
        note: None,
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

#[test]
fn file_transport_verifies_genesis_document() {
    let outbox = Outbox::genesis("node", "file:///unused");
    let path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
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
    let path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
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
    let url = serve_once("200 OK", serde_json::to_string(&outbox).unwrap());
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
    let url = serve_once("200 OK", serde_json::to_string(&outbox).unwrap());
    let record = Poller::new().poll_session("node", &session(url), 102);
    assert!(matches!(record.status, PollStatus::InvalidTrust { .. }));
}

#[test]
fn hmac_is_explicitly_unsupported_not_treated_as_valid() {
    let mut outbox = Outbox::genesis("node", "file:///unused");
    outbox.trust = TrustMode::Hmac;
    let path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let record =
        Poller::new().poll_session("node", &session(format!("file://{}", path.display())), 100);
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
    let url = serve_once("200 OK", serde_json::to_string(&outbox).unwrap());
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
    let path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "negative".into(),
        trust_model: "hmac".into(),
        sessions: BTreeMap::from([("node".into(), session(format!("file://{}", path.display())))]),
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
    let url = serve_once("200 OK", serde_json::to_string(&outbox).unwrap());
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
    let url = serve_once("200 OK", serde_json::to_string(&outbox).unwrap());
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
    let outbox_path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "cli-restart".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([(
            "node".into(),
            session(format!("file://{}", outbox_path.display())),
        )]),
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
    let outbox_path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "cli-invalid-state".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([(
            "node".into(),
            session(format!("file://{}", outbox_path.display())),
        )]),
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
    let record = Poller::new().poll_session(
        "oracle",
        &session(format!("file://{}", path.display())),
        100,
    );
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
    let outbox_path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let registry = Registry {
        schema_version: "test".into(),
        network_name: "alpha".into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([(
            "node".into(),
            session(format!("file://{}", outbox_path.display())),
        )]),
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
    let outbox_path = temp_file(&serde_json::to_string(&outbox).unwrap());
    let registry_for = |network: &str| Registry {
        schema_version: "test".into(),
        network_name: network.into(),
        trust_model: "unsigned-hash-chain".into(),
        sessions: BTreeMap::from([(
            "node".into(),
            session(format!("file://{}", outbox_path.display())),
        )]),
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
        json!("asfa-directive-ledger/v2")
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
    assert!(DirectiveLedger::load_for_network(&state, "alpha").is_ok());
    assert!(DirectiveLedger::load_for_network(&state, "beta").is_err());

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
    let mut ledger = DirectiveLedger::for_network("checkpoint-test");
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
    let mut restored =
        DirectiveLedger::load_for_network(&checkpoint_state, "checkpoint-test").unwrap();
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
