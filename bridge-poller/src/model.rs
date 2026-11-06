use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";
pub const REPORT_SCHEMA_VERSION: &str = "asfa-bridge-report/v1";

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TrustMode {
    #[default]
    UnsignedHashChain,
    Hmac,
    FullSignature,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Registry {
    pub schema_version: String,
    pub network_name: String,
    pub trust_model: String,
    pub sessions: BTreeMap<String, Session>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct Session {
    pub url: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub trust: TrustMode,
    #[serde(default)]
    pub note: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
        }
    }
}
