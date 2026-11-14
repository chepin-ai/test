# Outbox 与无签名哈希链协议 v1

## 1. 文档

`Outbox` 必填字段：`session`、`url`、`trust`、`hash_chain`；`directives`、`mailbox` 可省略。文档必须是 UTF-8 JSON，最大 2 MiB；Registry 最大 2 MiB 且最多 64 个会话，LedgerSnapshot 最大 16 MiB，均在读取时同时检查 metadata 和实际读回字节。注册表键名必须与文档 `session` 完全一致。Outbox、Registry 与 LedgerSnapshot 在 schema 转换前共用严格 JSON 入口，递归拒绝所有对象层级的重复成员；键名在 JSON 转义解码后比较，因此 `a` 与 `\u0061` 也判重。同一入口还强制根深度为 1、最大深度 64，以及全文档最多 16384 个 JSON 值节点；容器和标量各计一个节点，对象键不另计，所有分支共享计数器。协议结构使用 `deny_unknown_fields`，未知字段不会被静默当作“已验证签名”或其他扩展语义；`mailbox` 与区块 `payload` 仍是明确开放的数据字段，但同样不能绕过深度和节点预算。

文档自报 `Outbox.url` 必须等于会话的 `canonical_url`。未填写 `canonical_url` 时，正典 URL 默认就是读取 `url`；只有显式声明后，jsDelivr 等只读镜像地址才允许与正典地址不同。该检查是精确字符串身份对拍，不做 URL 语义归一化，也不认证镜像或发布者。

## 2. 哈希计算

所有哈希为小写 SHA-256 hex。负载哈希：

```text
payload_hash = SHA256(serde_json::to_vec(payload))
```

这是 V1 的确定性序列化契约，**不是完整 RFC 8785 JCS**。严格 JSON 消除重复键歧义并限制解析资源，不改变 V1 哈希域、数字格式或键排序规则。独立 Python 判读器仅覆盖无浮点、整数处于 `serde_json` 整数范围内的 V1 子集。

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

传输默认只接受 HTTPS。`http://` 必须显式设置 `allow_insecure_http=true`，`file://` 必须显式设置 `allow_file=true`；其他 scheme 和 URL fragment 在任何 I/O 前拒绝，HTTP(S) 还拒绝缺失主机与 URL userinfo。HTTP client 禁用自动重定向，300–399 均作为 `http_status` 负结果，第二跳不会被请求。单请求 15 秒超时和 2 MiB 响应上限继续保留。CLI 另在读取 Registry 前建立默认 60000ms 的全轮询 deadline，`--poll-timeout-ms` 只能调低到 1..=60000；每个 HTTP 请求的超时取单请求上限与当前剩余时间的较小值，会话之间及入库／波次保存前再次检查 deadline，超时整次运行非零失败。库 API 的旧 `poll_registry_detailed` 兼容入口只提供逐请求超时，处理不可信 Registry 必须调用 `poll_registry_detailed_with_deadline`。这些门禁不等于完整 SSRF 防护：DNS rebinding／pinning、私网与 metadata 地址、连接时 IP 绑定、出口防火墙和 DNS 超时仍需外层或后续实现。

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

账本使用 `(session, id)` 结构化键，避免字符串拼接碰撞。完全相同的重复指令返回 `Duplicate`；同键不同内容返回 `Conflict`；过期、空字段和来源不符分别返回负结果。`consume` 删除待办指令并保留 tombstone，再次收到同键指令返回 `Consumed`，不能重新入库。`pending_for_at` 与 `prune_expired` 会按当前时间重新检查过期状态。默认硬上限为 4096 个 pending、16384 个 tombstone、单 Outbox 1024 条已验证指令；CLI 可用 `--max-pending`、`--max-tombstones`、`--max-outbox-directives` 调低但不能调高。容量超限在写入前失败；tombstone 满时消费失败且待办指令不丢失。

`LedgerSnapshot` 使用 `asfa-directive-ledger/v3`，将网络身份、安全策略摘要、待办、tombstone 与每会话 `(height,latest)` 检查点以确定性数组表示。CLI 通过 `load_for_registry` 强制快照 `network_name` 与 `policy_hash` 同时等于当前 Registry；旧 v1／v2、无网络或无策略身份、跨网络及同网络安全策略变化均不做隐式迁移，加载失败不覆盖原文件。只修改说明性 `role`／`note` 不改变策略摘要，可以继续加载。

策略摘要的域分离定义为：

```text
policy_hash = SHA256(
  "ASFA-OS-XI/REGISTRY-POLICY/V1\n" || serde_json::to_vec(policy_projection)
)
```

`policy_projection` 包含 Registry `schema_version`、`network_name`、`trust_model`，以及每个 session 的读取 URL、解析后的正典 URL、trust、`allow_insecure_http` 和 `allow_file`。`role`／`note` 被明确排除。省略 `canonical_url` 与显式填写相同读取 URL 具有相同投影。该摘要是版本化、确定性的 SHA-256 投影，不是完整 JCS，也不是签名；能同时篡改 Registry 与 state 的本机攻击者仍可重算它。

`save_atomic` 使用同目录临时文件原子替换，并拒绝生成超过 16 MiB 的快照；恢复时校验 schema、重复／未知 JSON 成员、重复结构化键、非法指令、非法／重复检查点、“已消费但仍待办”矛盾及本地基数上限。恢复后重放仍返回 `Consumed`，历史分叉仍被拒绝。

检查点规则：新高度低于旧高度为 `Rollback`；同高不同 latest 为 `Fork`；更高高度在旧高度处的块哈希必须等于旧 latest，否则为 `Fork`。合法重读和保留旧前缀的延长放行。该检查是 O(n) 全链前缀对拍，不是 Merkle consistency proof；整份状态文件被替换仍需外部单调锚或独立 witness。持久化不是隐式副作用：调用方必须在状态变更后保存，否则重启只恢复到最后一次快照。CLI 在加载前取得 `<state>.lock` sidecar 的 OS 排他锁并持有到输出结束，锁竞争返回非零；sidecar 不随原子 rename 换 inode。它只约束使用相同词法路径的协作 CLI，不约束路径别名、非协作写者或跨主机锁。

## 5. CLI 入库与消费闭环

CLI 使用的 `poll_registry_detailed_with_deadline` 只在传输、严格 JSON、schema、trust 和完整哈希链全部通过时返回 `Outbox`，并在统一墙钟预算内完成全部会话。`ingest_outbox` 在修改账本前再次执行完整验证和本地检查点对拍，随后在克隆的暂存账本逐条执行并检查容量；任一伪造指令、链头冲突或容量超限都会丢弃整个暂存批次，原账本不变。只有全部成功才一次性替换内存账本并生成 `IngestionEvent`。

```text
StateLock.acquire(<state>.lock)
  → load_for_registry_with_limits(--state, network_name + policy_hash + local caps)
  → poll_registry_detailed_with_deadline（逐请求剩余时间＋会话间 deadline）
  → ingest_outbox（完整复验＋链头对拍＋暂存账本容量门禁）
  → 可选 consume(session, id)
  → 可选 plan_wave（只读）
  → deadline 复核
  → save_atomic(--state)
  → 输出 BridgeReport.ingestion / qfos-wave-plan/v1
```

`--consume-session` 与 `--consume-id` 必须成对提供，且消费必须同时指定 `--state`；`--state` 与 `--out` 不得相同。状态文件不存在时从空账本开始，存在但无法解析或恢复矛盾时直接失败，不覆盖原文件。`state_saved=true` 只表示本次原子保存已返回成功，不表示收到外部 ACK。

`ingestion` 汇总 `inserted`、`duplicate`、`replayed_consumed`、`conflict`、`expired`、`invalid`、`chain_checkpoints`、`pending`、`tombstones` 和逐指令事件；`chain_checkpoints` 统计完成本地一致性对拍并提交的会话检查点次数。`--fail-on-error` 将轮询失败、`conflict`、`invalid` 或消费 `not_found` 转为非零退出；`duplicate`、`replayed_consumed` 与 `expired` 是已显式分类的协议结果，不单独触发该门禁。

### 5.1 QF-OS 波次计划

`--wave-out` 要求同时使用 `--state`，默认目标为 `qfos`；`--wave-target` 可显式选择其他目标。计划只从当前账本中未过期且 `to` 等于目标或 `*` 的指令生成。各来源先按 session、指令 ID 确定顺序，再以来源轮转准入；`--wave-max-jobs` 与 `--wave-max-per-source` 分别限制全局和单来源名额，且只能调低到不高于 64／16。未准入项明确分为 `deferred_wave_quota` 或 `deferred_source_quota`，两者同时可能时以来源配额优先。

```text
ledger_hash = SHA256(
  "ASFA-OS-XI/DIRECTIVE-LEDGER-SNAPSHOT/V1\n" || serde_json::to_vec(snapshot)
)
plan_hash = SHA256(
  "ASFA-OS-XI/QFOS-WAVE-PLAN/V1\n" || serde_json::to_vec(plan_without_plan_hash)
)
```

计划绑定 `network_name`、`policy_hash`、完整 `ledger_hash`、目标、本地时间输入、双配额、逐 Job 内容及逐来源计数。`mode` 固定为 `plan-only-no-execution`：生成计划不消费指令、不执行 action、不调用 Skill，也不证明引擎执行结果。独立 Python 判读器从 Registry 与原始 snapshot 重建整个计划，支持无浮点的 V1 子集，不是 JCS 或签名验证器。QIOS 标识在当前仓内与已核验定义中均未解析，本协议不作 QIOS 适配或兼容声称。

## 6. 负结果

`http_status`、`transport`、`invalid_json`、`invalid_schema`、`invalid_trust`、`unsupported_trust` 都保留在报告中。重定向、正典 URL 错配、未知字段、未授权 scheme、超限输入、解析失败均不得静默跳过。策略／版本恢复失败发生在轮询之前，因此不生成新报告、不覆盖原状态。全轮询 deadline 是整次 CLI 错误而非降级为普通成功报告；超时发生在状态保存前时不生成报告或新状态。开放 Outbox 字段的深度／节点超限分类为 `invalid_json`，配合 `--fail-on-error` 返回非零。

64 层与 16384 节点是应用自身预算，不再依赖 serde_json 默认递归限制充当安全边界。session 数、pending／tombstone／单 Outbox 基数和协作 CLI 写者锁也已具备门禁；这些仍不能替代非协作写者防护、路径规范化、CAS、WAL、分布式协调、完整 DNS 超时覆盖或进程级内存／CPU 隔离。
