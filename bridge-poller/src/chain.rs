use crate::model::{ChainBlock, Directive, HashChain, Outbox, TrustMode, GENESIS_HASH};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

const HASH_DOMAIN: &str = "ASFA-OS-XI/UNSIGNED-HASH-CHAIN/V1";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ChainError {
    #[error("unsupported trust mode: {0:?}")]
    UnsupportedTrust(TrustMode),
    #[error("invalid genesis hash")]
    InvalidGenesis,
    #[error("declared height {declared} does not match block count {actual}")]
    HeightMismatch { declared: u64, actual: usize },
    #[error("zero-height chain must not contain blocks")]
    BlocksAtZeroHeight,
    #[error("latest hash does not match the terminal block")]
    InvalidLatest,
    #[error("unexpected block height at position {position}: found {actual}")]
    NonSequentialHeight { position: usize, actual: u64 },
    #[error("previous hash mismatch at block {height}")]
    PreviousHashMismatch { height: u64 },
    #[error("payload hash mismatch at block {height}")]
    PayloadHashMismatch { height: u64 },
    #[error("block hash mismatch at block {height}")]
    BlockHashMismatch { height: u64 },
    #[error("invalid directive block at height {height}: {reason}")]
    InvalidDirectiveBlock { height: u64, reason: String },
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn payload_digest(payload: &Value) -> String {
    let encoded = serde_json::to_vec(payload).expect("serde_json::Value always serializes");
    sha256_hex(&encoded)
}

fn block_digest(
    height: u64,
    previous_hash: &str,
    payload_hash: &str,
    timestamp: u64,
    nonce: u64,
) -> String {
    let canonical =
        format!("{HASH_DOMAIN}\n{height}\n{previous_hash}\n{payload_hash}\n{timestamp}\n{nonce}");
    sha256_hex(canonical.as_bytes())
}

pub fn make_block(
    height: u64,
    previous_hash: &str,
    payload: Value,
    timestamp: u64,
    nonce: u64,
) -> ChainBlock {
    let payload_hash = payload_digest(&payload);
    let hash = block_digest(height, previous_hash, &payload_hash, timestamp, nonce);
    ChainBlock {
        height,
        previous_hash: previous_hash.into(),
        payload,
        payload_hash,
        timestamp,
        nonce,
        hash,
    }
}

/// Verify every block and the terminal pointer. This proves internal consistency
/// of the unsigned chain; it does not authenticate the publisher's identity.
pub fn verify_chain(chain: &HashChain) -> Result<u64, ChainError> {
    if chain.genesis != GENESIS_HASH {
        return Err(ChainError::InvalidGenesis);
    }
    if chain.height == 0 {
        if !chain.blocks.is_empty() {
            return Err(ChainError::BlocksAtZeroHeight);
        }
        if chain.latest != chain.genesis {
            return Err(ChainError::InvalidLatest);
        }
        return Ok(0);
    }
    if chain.height as usize != chain.blocks.len() {
        return Err(ChainError::HeightMismatch {
            declared: chain.height,
            actual: chain.blocks.len(),
        });
    }

    let mut expected_previous = chain.genesis.clone();
    for (index, block) in chain.blocks.iter().enumerate() {
        let expected_height = index as u64 + 1;
        if block.height != expected_height {
            return Err(ChainError::NonSequentialHeight {
                position: index,
                actual: block.height,
            });
        }
        if block.previous_hash != expected_previous {
            return Err(ChainError::PreviousHashMismatch {
                height: block.height,
            });
        }
        let expected_payload_hash = payload_digest(&block.payload);
        if block.payload_hash != expected_payload_hash {
            return Err(ChainError::PayloadHashMismatch {
                height: block.height,
            });
        }
        let expected_hash = block_digest(
            block.height,
            &block.previous_hash,
            &block.payload_hash,
            block.timestamp,
            block.nonce,
        );
        if block.hash != expected_hash {
            return Err(ChainError::BlockHashMismatch {
                height: block.height,
            });
        }
        expected_previous = block.hash.clone();
    }
    if chain.latest != expected_previous {
        return Err(ChainError::InvalidLatest);
    }
    Ok(chain.height)
}

pub fn verify_outbox(outbox: &Outbox) -> Result<u64, ChainError> {
    if outbox.trust != TrustMode::UnsignedHashChain {
        return Err(ChainError::UnsupportedTrust(outbox.trust));
    }
    verify_chain(&outbox.hash_chain)
}

pub fn append_block(
    outbox: &mut Outbox,
    payload: Value,
    timestamp: u64,
    nonce: u64,
) -> Result<ChainBlock, ChainError> {
    verify_outbox(outbox)?;
    let height = outbox.hash_chain.height + 1;
    let block = make_block(height, &outbox.hash_chain.latest, payload, timestamp, nonce);
    outbox.hash_chain.latest = block.hash.clone();
    outbox.hash_chain.height = height;
    outbox.hash_chain.blocks.push(block.clone());
    Ok(block)
}

/// Bind directives to a verified block. Top-level `Outbox.directives` is legacy
/// metadata and is deliberately excluded from trusted ingestion.
pub fn append_directives(
    outbox: &mut Outbox,
    directives: Vec<Directive>,
    timestamp: u64,
    nonce: u64,
) -> Result<ChainBlock, ChainError> {
    append_block(
        outbox,
        serde_json::json!({"kind": "directives", "directives": directives}),
        timestamp,
        nonce,
    )
}

pub fn verified_directives(outbox: &Outbox) -> Result<Vec<Directive>, ChainError> {
    verify_outbox(outbox)?;
    let mut directives = Vec::new();
    for block in &outbox.hash_chain.blocks {
        if block.payload.get("kind").and_then(Value::as_str) == Some("directives") {
            let payload = block.payload.get("directives").ok_or_else(|| {
                ChainError::InvalidDirectiveBlock {
                    height: block.height,
                    reason: "missing directives array".into(),
                }
            })?;
            let mut block_directives: Vec<Directive> = serde_json::from_value(payload.clone())
                .map_err(|error| ChainError::InvalidDirectiveBlock {
                    height: block.height,
                    reason: error.to_string(),
                })?;
            directives.append(&mut block_directives);
        }
    }
    Ok(directives)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn genesis_is_valid_only_with_zero_height() {
        let outbox = Outbox::genesis("a", "file:///a.json");
        assert_eq!(verify_outbox(&outbox), Ok(0));
    }

    #[test]
    fn appended_blocks_verify_and_tampering_fails() {
        let mut outbox = Outbox::genesis("a", "file:///a.json");
        append_block(&mut outbox, json!({"n": 1}), 100, 0).unwrap();
        append_block(&mut outbox, json!({"n": 2}), 101, 0).unwrap();
        assert_eq!(verify_outbox(&outbox), Ok(2));
        outbox.hash_chain.blocks[0].payload = json!({"n": 99});
        assert_eq!(
            verify_outbox(&outbox),
            Err(ChainError::PayloadHashMismatch { height: 1 })
        );
    }

    #[test]
    fn broken_previous_link_fails_closed() {
        let mut outbox = Outbox::genesis("a", "file:///a.json");
        append_block(&mut outbox, json!({"n": 1}), 100, 0).unwrap();
        append_block(&mut outbox, json!({"n": 2}), 101, 0).unwrap();
        outbox.hash_chain.blocks[1].previous_hash = "bad".into();
        assert_eq!(
            verify_outbox(&outbox),
            Err(ChainError::PreviousHashMismatch { height: 2 })
        );
    }

    #[test]
    fn directives_are_bound_to_blocks_not_legacy_metadata() {
        let mut outbox = Outbox::genesis("a", "file:///a.json");
        outbox.directives.push(Directive {
            id: "untrusted".into(),
            from: "a".into(),
            to: "b".into(),
            action: "Ping".into(),
            payload: json!({}),
            expires_epoch: None,
        });
        append_directives(
            &mut outbox,
            vec![Directive {
                id: "trusted".into(),
                from: "a".into(),
                to: "b".into(),
                action: "Ping".into(),
                payload: json!({}),
                expires_epoch: Some(200),
            }],
            100,
            0,
        )
        .unwrap();
        let directives = verified_directives(&outbox).unwrap();
        assert_eq!(directives.len(), 1);
        assert_eq!(directives[0].id, "trusted");
    }
}
