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

HTTP 200、JSON 可解析或字段自报 `active` 均不等于验证通过。

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

顶层 `Outbox.directives` 仅为兼容元数据，不计入可信指令。账本键为 `{session}/{id}`，防止跨会话 ID 冲突；重复、过期和空 ID 分别返回负结果；`consume` 为单次删除语义。

## 5. 负结果

`http_status`、`transport`、`invalid_json`、`invalid_schema`、`invalid_trust`、`unsupported_trust` 都保留在报告中。禁止解析失败后静默跳过。
