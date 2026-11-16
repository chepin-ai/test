use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const REPORT_SCHEMA_VERSION: &str = "asfa-bridge-report/v1";
pub const POLICY_DIGEST_DOMAIN: &str = "ASFA-OS-XI/REGISTRY-POLICY/V1\n";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TrustMode {
    #[default]
    UnsignedHashChain,
    Hmac,
    FullSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema_version: String,
    pub network_name: String,
    pub trust_model: String,
    pub sessions: BTreeMap<String, Session>,
}

impl Registry {
    /// Deterministic digest of the complete security-relevant policy projection.
    /// Descriptive role/note fields are deliberately excluded. This is a versioned
    /// domain-separated SHA-256 digest, not a signature or an RFC 8785 JCS claim.
    pub fn policy_digest(&self) -> String {
        let sessions: BTreeMap<String, Value> = self
            .sessions
            .iter()
            .map(|(name, session)| {
                (
                    name.clone(),
                    json!({
                        "url": session.url,
                        "canonical_url": session.canonical_url(),
                        "trust": session.trust,
                        "allow_insecure_http": session.allow_insecure_http,
                        "allow_file": session.allow_file,
                    }),
                )
            })
            .collect();
        let projection = json!({
            "schema_version": self.schema_version,
            "network_name": self.network_name,
            "trust_model": self.trust_model,
            "sessions": sessions,
        });
        let mut encoded = POLICY_DIGEST_DOMAIN.as_bytes().to_vec();
        encoded.extend(
            serde_json::to_vec(&projection).expect("registry policy projection always serializes"),
        );
        format!("{:x}", Sha256::digest(&encoded))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Session {
    /// Fetch URL. A read-only mirror may differ from the canonical document URL.
    pub url: String,
    /// Expected Outbox.url. Omitted means exact equality with the fetch URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_url: Option<String>,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub trust: TrustMode,
    #[serde(default)]
    pub note: Option<String>,
    /// HTTP is denied unless this explicit test/legacy opt-in is present.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// Local file transport is denied unless explicitly enabled.
    #[serde(default)]
    pub allow_file: bool,
}

impl Session {
    pub fn canonical_url(&self) -> &str {
        self.canonical_url.as_deref().unwrap_or(&self.url)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Directive {
    pub id: String,
    pub from: String,
    pub to: String,
    pub action: String,
    #[serde(default)]
    pub payload: Value,
    #[serde(default)]
    pub expires_epoch: Option<u64>,
}

pub const EXECUTION_INPUT_DIGEST_DOMAIN: &str = "ASFA-OS-XI/QFOS-EXECUTION-INPUT/V1\n";
pub const EXECUTION_OUTPUT_DIGEST_DOMAIN: &str = "ASFA-OS-XI/QFOS-EXECUTION-OUTPUT/V1\n";
pub const EXECUTION_RECEIPT_DIGEST_DOMAIN: &str = "ASFA-OS-XI/QFOS-EXECUTION-RECEIPT/V1\n";
pub const EXECUTION_DEAD_LETTER_DIGEST_DOMAIN: &str = "ASFA-OS-XI/QFOS-DEAD-LETTER/V1\n";

fn execution_digest(domain: &str, value: &Value) -> String {
    let mut encoded = domain.as_bytes().to_vec();
    encoded.extend(serde_json::to_vec(value).expect("execution projection always serializes"));
    format!("{:x}", Sha256::digest(&encoded))
}

pub fn execution_input_digest(
    session: &str,
    id: &str,
    action: &str,
    payload: &Value,
    expires_epoch: Option<u64>,
) -> String {
    execution_digest(
        EXECUTION_INPUT_DIGEST_DOMAIN,
        &json!({
            "session": session,
            "id": id,
            "action": action,
            "payload": payload,
            "expires_epoch": expires_epoch,
        }),
    )
}

pub fn execution_output_digest(output: &Value) -> String {
    execution_digest(EXECUTION_OUTPUT_DIGEST_DOMAIN, output)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionReceipt {
    pub session: String,
    pub id: String,
    pub action: String,
    pub engine: String,
    pub plan_hash: String,
    pub input_hash: String,
    pub output: Value,
    pub output_hash: String,
    pub executed_at_epoch: u64,
    pub receipt_hash: String,
}

impl ExecutionReceipt {
    pub fn compute_hash(&self) -> String {
        execution_digest(
            EXECUTION_RECEIPT_DIGEST_DOMAIN,
            &json!({
                "session": self.session,
                "id": self.id,
                "action": self.action,
                "engine": self.engine,
                "plan_hash": self.plan_hash,
                "input_hash": self.input_hash,
                "output": self.output,
                "output_hash": self.output_hash,
                "executed_at_epoch": self.executed_at_epoch,
            }),
        )
    }

    pub fn refresh_hash(&mut self) {
        self.receipt_hash = self.compute_hash();
    }

    pub fn has_valid_hash(&self) -> bool {
        self.receipt_hash == self.compute_hash()
            && self.output_hash == execution_output_digest(&self.output)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DeadLetterRecord {
    pub session: String,
    pub id: String,
    pub action: String,
    pub engine: String,
    pub plan_hash: String,
    pub input_hash: String,
    pub code: String,
    pub message: String,
    pub failed_at_epoch: u64,
    pub dead_letter_hash: String,
}

impl DeadLetterRecord {
    pub fn compute_hash(&self) -> String {
        execution_digest(
            EXECUTION_DEAD_LETTER_DIGEST_DOMAIN,
            &json!({
                "session": self.session,
                "id": self.id,
                "action": self.action,
                "engine": self.engine,
                "plan_hash": self.plan_hash,
                "input_hash": self.input_hash,
                "code": self.code,
                "message": self.message,
                "failed_at_epoch": self.failed_at_epoch,
            }),
        )
    }

    pub fn refresh_hash(&mut self) {
        self.dead_letter_hash = self.compute_hash();
    }

    pub fn has_valid_hash(&self) -> bool {
        self.dead_letter_hash == self.compute_hash()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChainBlock {
    pub height: u64,
    pub previous_hash: String,
    pub payload: Value,
    pub payload_hash: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HashChain {
    pub genesis: String,
    pub latest: String,
    pub height: u64,
    #[serde(default)]
    pub blocks: Vec<ChainBlock>,
}

impl Default for HashChain {
    fn default() -> Self {
        Self {
            genesis: GENESIS_HASH.into(),
            latest: GENESIS_HASH.into(),
            height: 0,
            blocks: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Outbox {
    pub session: String,
    pub url: String,
    pub trust: TrustMode,
    #[serde(default)]
    pub directives: Vec<Directive>,
    #[serde(default)]
    pub mailbox: Value,
    pub hash_chain: HashChain,
}

impl Outbox {
    pub fn genesis(session: impl Into<String>, url: impl Into<String>) -> Self {
        Self {
            session: session.into(),
            url: url.into(),
            trust: TrustMode::UnsignedHashChain,
            directives: Vec::new(),
            mailbox: json!({}),
            hash_chain: HashChain::default(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PollStatus {
    Verified {
        verified_blocks: u64,
        verified_directives: usize,
        untrusted_directives: usize,
    },
    HttpStatus {
        code: u16,
    },
    Transport {
        message: String,
    },
    BlockedEgress {
        message: String,
    },
    InvalidJson {
        message: String,
    },
    InvalidSchema {
        message: String,
    },
    InvalidTrust {
        message: String,
    },
    UnsupportedTrust {
        mode: TrustMode,
    },
}

impl PollStatus {
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct PollRecord {
    pub session: String,
    pub url: String,
    pub fetched_at_epoch: u64,
    pub status: PollStatus,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SessionPoll {
    pub record: PollRecord,
    pub outbox: Option<Outbox>,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct IngestionEvent {
    pub session: String,
    pub id: String,
    pub outcome: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct IngestionReport {
    pub inserted: usize,
    pub duplicate: usize,
    pub replayed_consumed: usize,
    pub conflict: usize,
    pub expired: usize,
    pub invalid: usize,
    pub chain_checkpoints: usize,
    pub pending: usize,
    pub tombstones: usize,
    pub state_saved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consume_result: Option<String>,
    pub events: Vec<IngestionEvent>,
}

impl IngestionReport {
    pub fn merge(&mut self, mut other: Self) {
        self.inserted += other.inserted;
        self.duplicate += other.duplicate;
        self.replayed_consumed += other.replayed_consumed;
        self.conflict += other.conflict;
        self.expired += other.expired;
        self.invalid += other.invalid;
        self.chain_checkpoints += other.chain_checkpoints;
        self.pending = other.pending;
        self.tombstones = other.tombstones;
        self.state_saved |= other.state_saved;
        if other.consume_result.is_some() {
            self.consume_result = other.consume_result.take();
        }
        self.events.append(&mut other.events);
    }
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct ReportSummary {
    pub total: usize,
    pub verified: usize,
    pub failed: usize,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct BridgeReport {
    pub schema_version: String,
    pub network_name: String,
    pub generated_at_epoch: u64,
    pub summary: ReportSummary,
    pub records: Vec<PollRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingestion: Option<IngestionReport>,
}

impl BridgeReport {
    pub fn new(network_name: String, generated_at_epoch: u64, records: Vec<PollRecord>) -> Self {
        let verified = records
            .iter()
            .filter(|record| record.status.is_verified())
            .count();
        let summary = ReportSummary {
            total: records.len(),
            verified,
            failed: records.len() - verified,
        };
        Self {
            schema_version: REPORT_SCHEMA_VERSION.into(),
            network_name,
            generated_at_epoch,
            summary,
            records,
            ingestion: None,
        }
    }
}
