#!/usr/bin/env python3
"""Independent iterative JSON depth/node oracle; no Rust artifacts are reused."""
import json
import sys

MAX_DEPTH = 64
MAX_NODES = 16_384


def no_duplicate_members(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object member: {key!r}")
        result[key] = value
    return result


def inspect_bytes(data, max_depth=MAX_DEPTH, max_nodes=MAX_NODES):
    root = json.loads(data, object_pairs_hook=no_duplicate_members)
    stack = [(root, 1)]
    nodes = 0
    observed_depth = 0
    while stack:
        value, depth = stack.pop()
        if depth > max_depth:
            raise ValueError(
                f"JSON depth budget exceeded: limit={max_depth}, next_depth={depth}"
            )
        nodes += 1
        if nodes > max_nodes:
            raise ValueError(
                f"JSON node budget exceeded: limit={max_nodes}, next_node={nodes}"
            )
        observed_depth = max(observed_depth, depth)
        if isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)
        elif isinstance(value, dict):
            # Keys are not independent JSON values in the Rust budget model.
            stack.extend((child, depth + 1) for child in value.values())
    return {"nodes": nodes, "max_depth": observed_depth}


def nested_arrays(depth):
    return "[" * depth + "0" + "]" * depth


def self_tests():
    accepted_depth = nested_arrays(63)
    rejected_depth = nested_arrays(64)
    assert inspect_bytes(accepted_depth) == {"nodes": 64, "max_depth": 64}
    assert inspect_bytes("[[1,2],[3,4]]") == {"nodes": 7, "max_depth": 3}
    assert inspect_bytes("[" + ",".join(["0"] * (MAX_NODES - 1)) + "]")["nodes"] == MAX_NODES
    for payload, expected in [
        (rejected_depth, "depth budget exceeded"),
        ("[" + ",".join(["0"] * MAX_NODES) + "]", "node budget exceeded"),
        ('{"a":1,"\\u0061":2}', "duplicate JSON object member"),
    ]:
        try:
            inspect_bytes(payload)
        except ValueError as error:
            assert expected in str(error), error
        else:
            raise AssertionError(f"oracle accepted known-bad input: {expected}")
    return 5


def main():
    if len(sys.argv) == 1:
        count = self_tests()
        print(
            f"json_budget_oracle=PASS depth_limit={MAX_DEPTH} "
            f"node_limit={MAX_NODES} self_tests={count}"
        )
        return 0
    if len(sys.argv) == 3 and sys.argv[1] == "--check":
        try:
            with open(sys.argv[2], "rb") as source:
                metrics = inspect_bytes(source.read())
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            print(json.dumps({"verdict": "rejected", "reason": str(error)}, ensure_ascii=False))
            return 2
        print(json.dumps({"verdict": "accepted", **metrics}, ensure_ascii=False))
        return 0
    print(f"usage: {sys.argv[0]} [--check document.json]", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
