# Outbox 与无签名哈希链协议 v1

## 1. 文档

`Outbox` 必填字段：`session`、`url`、`trust`、`hash_chain`；`directives`、`mailbox` 可省略。文档必须是 UTF-8 JSON，最大 2 MiB。注册表键名必须与文档 `session` 完全一致。

## 2. 哈希计算

所有哈希为小写 SHA-256 hex。负载哈希：

```text
payload_hash = SHA256(serde_json::to_vec(payload))
```

区块哈希的规范输入为 UTF-8 文本：

```text
ASFA-OS-XI/UNSIGNED-HASH-CHAIN/V1\n
{height}\n
{previous_hash}\n
{payload_hash}\n
{timestamp}\n
{nonce}
```

`genesis` 为 64 个 `0`。零高度时 `blocks=[]` 且 `latest=genesis`。非零高度必须满足：块数等于高度、块高从 1 连续递增、`previous_hash` 链接前块哈希、负载哈希与区块哈希均可重算、`latest` 等于终端块哈希。

## 3. 信任分级

- `unsigned-hash-chain`：已实现。只证明内部一致性，**不证明发布者身份**。
- `hmac`：未实现，返回 `unsupported_trust`。
- `full-signature`：未实现，返回 `unsupported_trust`。

注册表顶层 `trust_model`、会话 `trust` 和文档 `trust` 必须一致且均为 `unsigned-hash-chain`。不支持的会话模式在发起网络读取前即拒绝。HTTP 200、JSON 可解析或字段自报 `active` 均不等于验证通过。

## 4. 指令

可信指令放在区块负载中：

```json
{
  "kind": "directives",
  "directives": [
    {
      "id": "unique-id",
      "from": "asfa-ai",
      "to": "cisvr",
      "action": "Ping",
      "payload": {},
      "expires_epoch": 4102444800
    }
  ]
}
```

顶层 `Outbox.directives` 仅为兼容元数据，不计入可信指令。区块指令必须满足 `from == Outbox.session`，且 `id`、`to`、`action` 非空；追加伪造指令时，生成端在修改链之前拒绝。

账本使用 `(session, id)` 结构化键，避免字符串拼接碰撞。完全相同的重复指令返回 `Duplicate`；同键不同内容返回 `Conflict`；过期、空字段和来源不符分别返回负结果。`consume` 删除待办指令并保留 tombstone，再次收到同键指令返回 `Consumed`，不能重新入库。`pending_for_at` 与 `prune_expired` 会按当前时间重新检查过期状态。

`LedgerSnapshot` 使用 `asfa-directive-ledger/v1`，将待办与 tombstone 以确定性数组表示；`save_atomic` 同目录临时文件原子替换，`load` 限制 16 MiB 并校验 schema、重复键、非法指令及“已消费但仍待办”矛盾。恢复后重放仍返回 `Consumed`。持久化不是隐式副作用：调用方必须在状态变更后保存，否则重启只恢复到最后一次快照。

## 5. CLI 入库与消费闭环

`poll_registry_detailed` 只在传输、schema、trust 和完整哈希链全部通过时返回 `Outbox`。`ingest_outbox` 在修改账本前再次执行完整验证；因此后续区块即使只有一个伪造指令，也不会部分应用前面的合法区块。随后才逐条写入账本并生成 `IngestionEvent`。

```text
load --state
  → poll_registry_detailed
  → ingest_outbox（仅 verified Outbox）
  → 可选 consume(session, id)
  → save_atomic(--state)
  → 输出 BridgeReport.ingestion
```

`--consume-session` 与 `--consume-id` 必须成对提供，且消费必须同时指定 `--state`；`--state` 与 `--out` 不得相同。状态文件不存在时从空账本开始，存在但无法解析或恢复矛盾时直接失败，不覆盖原文件。`state_saved=true` 只表示本次原子保存已返回成功，不表示收到外部 ACK。

`ingestion` 汇总 `inserted`、`duplicate`、`replayed_consumed`、`conflict`、`expired`、`invalid`、`pending`、`tombstones` 和逐指令事件。`--fail-on-error` 将轮询失败、`conflict`、`invalid` 或消费 `not_found` 转为非零退出；`duplicate`、`replayed_consumed` 与 `expired` 是已显式分类的协议结果，不单独触发该门禁。

## 6. 负结果

`http_status`、`transport`、`invalid_json`、`invalid_schema`、`invalid_trust`、`unsupported_trust` 都保留在报告中。禁止解析失败后静默跳过。
