#!/usr/bin/env python3
"""Independent Python oracle for the no-float ASFA V1 chain subset.

This is not a JCS implementation. It deliberately rejects floats so Python and
Rust number formatting cannot be silently conflated.
"""

import argparse
import copy
import hashlib
import json
from pathlib import Path

DOMAIN = "ASFA-OS-XI/UNSIGNED-HASH-CHAIN/V1"
GENESIS = "0" * 64
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
UINT64_MAX = 2**64 - 1
INT64_MIN = -(2**63)


class VerificationError(ValueError):
    pass


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise VerificationError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    raise VerificationError(f"non-finite number is outside the oracle profile: {value}")


def parse_document(raw):
    if len(raw) > MAX_DOCUMENT_BYTES:
        raise VerificationError("document exceeds 2 MiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise VerificationError("document is not valid UTF-8") from error
    try:
        return json.loads(
            text, object_pairs_hook=unique_object, parse_constant=reject_constant
        )
    except (json.JSONDecodeError, UnicodeError) as error:
        raise VerificationError(f"invalid JSON: {error}") from error


def canonical_bytes(value):
    def check(node):
        if isinstance(node, float):
            raise VerificationError("float is outside the no-float oracle profile")
        if type(node) is int and not (INT64_MIN <= node <= UINT64_MAX):
            raise VerificationError("integer is outside Rust serde_json's integer range")
        if isinstance(node, dict):
            for key, child in node.items():
                if not isinstance(key, str):
                    raise VerificationError("JSON object key is not a string")
                check(key)
                check(child)
        elif isinstance(node, list):
            for child in node:
                check(child)
        elif isinstance(node, str):
            try:
                node.encode("utf-8")
            except UnicodeEncodeError as error:
                raise VerificationError("unpaired surrogate is rejected") from error

    check(value)
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        return rendered.encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise VerificationError(f"cannot canonicalize V1 subset: {error}") from error


def uint64(value, label):
    if type(value) is not int or not (0 <= value <= UINT64_MAX):
        raise VerificationError(f"{label} must be an unsigned 64-bit integer")
    return value


def payload_digest(payload):
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def verify_document(document):
    if not isinstance(document, dict):
        raise VerificationError("outbox must be an object")
    if document.get("trust") != "unsigned-hash-chain":
        raise VerificationError("unsupported trust mode")
    session = document.get("session")
    if not isinstance(session, str) or not session.strip():
        raise VerificationError("session must be a non-empty string")
    chain = document.get("hash_chain")
    if not isinstance(chain, dict) or chain.get("genesis") != GENESIS:
        raise VerificationError("invalid genesis")
    height = uint64(chain.get("height"), "chain height")
    blocks = chain.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != height:
        raise VerificationError("chain height does not match block count")
    previous = GENESIS
    directive_count = 0
    for index, block in enumerate(blocks, start=1):
        if not isinstance(block, dict):
            raise VerificationError(f"block {index} is not an object")
        if uint64(block.get("height"), f"block {index} height") != index:
            raise VerificationError(f"non-sequential block height at {index}")
        if block.get("previous_hash") != previous:
            raise VerificationError(f"previous hash mismatch at block {index}")
        timestamp = uint64(block.get("timestamp"), f"block {index} timestamp")
        nonce = uint64(block.get("nonce"), f"block {index} nonce")
        computed_payload_hash = payload_digest(block.get("payload"))
        if block.get("payload_hash") != computed_payload_hash:
            raise VerificationError(f"payload hash mismatch at block {index}")
        preimage = (
            f"{DOMAIN}\n{index}\n{previous}\n{computed_payload_hash}\n"
            f"{timestamp}\n{nonce}"
        ).encode("utf-8")
        computed_hash = hashlib.sha256(preimage).hexdigest()
        if block.get("hash") != computed_hash:
            raise VerificationError(f"block hash mismatch at block {index}")
        previous = computed_hash

        payload = block.get("payload")
        if isinstance(payload, dict) and payload.get("kind") == "directives":
            directives = payload.get("directives")
            if not isinstance(directives, list):
                raise VerificationError(f"missing directives array at block {index}")
            for directive in directives:
                if not isinstance(directive, dict):
                    raise VerificationError(f"invalid directive at block {index}")
                if directive.get("from") != session:
                    raise VerificationError(f"directive source mismatch at block {index}")
                for field in ("id", "to", "action"):
                    value = directive.get(field)
                    if not isinstance(value, str) or not value.strip():
                        raise VerificationError(
                            f"directive {field} is empty at block {index}"
                        )
                directive_count += 1
    if chain.get("latest") != previous:
        raise VerificationError("latest hash does not match terminal block")
    return {
        "session": session,
        "height": height,
        "latest": previous,
        "verified_directives": directive_count,
    }


def expect_rejection(callback, label):
    try:
        callback()
    except VerificationError:
        return {"case": label, "verdict": "rejected"}
    raise VerificationError(f"self-test was not rejected: {label}")


def verify_path(path, self_test):
    raw = path.read_bytes()
    document = parse_document(raw)
    result = verify_document(document)
    result.update(
        {
            "path": str(path),
            "document_sha256": hashlib.sha256(raw).hexdigest(),
            "verdict": "verified",
        }
    )
    if self_test:
        tests = [
            expect_rejection(
                lambda: parse_document(b'{"a":1,"\\u0061":2}'),
                "escaped_duplicate_member",
            )
        ]
        tampered = copy.deepcopy(document)
        if tampered["hash_chain"]["blocks"]:
            payload = tampered["hash_chain"]["blocks"][0]["payload"]
            if not isinstance(payload, dict):
                raise VerificationError("self-test payload must be an object")
            payload["__oracle_tamper__"] = True
        else:
            tampered["hash_chain"]["latest"] = "1" * 64
        tests.append(
            expect_rejection(lambda: verify_document(tampered), "tampered_chain")
        )
        result["self_test"] = tests
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    results = [verify_path(path, args.self_test) for path in args.paths]
    print(
        json.dumps(
            {
                "oracle_profile": "asfa-v1-python/no-floats/non-jcs",
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except (VerificationError, OSError) as error:
        raise SystemExit(f"independent oracle: {error}") from error
