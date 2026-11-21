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

传输默认只接受 HTTPS。`http://` 必须显式设置 `allow_insecure_http=true`，`file://` 必须显式设置 `allow_file=true`；其他 scheme 和 URL fragment 在任何 I/O 前拒绝，HTTP(S) 还拒绝缺失主机与 URL userinfo。HTTP client 禁用自动重定向，300–399 均作为 `http_status` 负结果，第二跳不会被请求。单请求 15 秒超时和 2 MiB 响应上限继续保留。CLI 另在读取 Registry 前建立默认 60000ms 的全轮询 deadline，`--poll-timeout-ms` 只能调低到 1..=60000；每个 HTTP 请求的超时取单请求上限与当前剩余时间的较小值，会话之间及入库／波次保存前再次检查 deadline，超时整次运行非零失败。库 API 的旧 `poll_registry_detailed` 兼容入口只提供逐请求超时，处理不可信 Registry 必须调用 `poll_registry_detailed_with_deadline`。

HTTP(S) 默认使用 `EgressPolicy::PublicOnly`。IP 字面量不经过 DNS，直接进行分类；域名在有界 worker 中解析一次，空答案、超过 32 个答案或组内任一非公开地址均使整组失败。验证后的 IP 与原 URL 端口重新构造并去重，实际 one-shot HTTP agent 的 resolver 只返回这组固定地址；请求仍使用原 URL，因此保留原 Host 与 TLS server name，而不是把 URL 改写成 IP。连接、读、写只获得扣除解析耗时后的剩余预算；重定向为零、环境代理关闭、连接池禁用。

默认拒绝未指定／当前网络、私网、shared／CGNAT、loopback、link-local、IETF protocol、documentation、transition、benchmarking、multicast、reserved，以及 IPv6 未指定、loopback、IPv4-mapped、NAT64、discard、IETF／transition、documentation、6to4、ULA、link-local、multicast 和非 `2000::/3` 地址。翻译／过渡形式整体 fail-closed，不因内嵌公网 IPv4 而自动信任。命中的非公开目的地址产生 `blocked_egress`；解析为空、过多、失败或调用方等待超时仍为 `transport` 并附具体原因。

`--allow-non-public-egress` 是仅供本地测试与受控遗留部署的显式进程级开关；它不是 `Session` 字段，不能由不可信 Registry／Outbox 开启，也不会关闭空答案、数量上限、原端口重构或禁代理检查。该门禁只覆盖本 HTTP client：不等同于 network namespace、外层 egress proxy、hostile OS 防护或通用 SSRF 防护。DNS 等待超时会释放调用方且 worker 不持有 HTTP agent，但不声称底层系统解析被强制取消或阻塞线程已被资源隔离。

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

`LedgerSnapshot` 在无票时使用 `asfa-directive-ledger/v4`，含非空票账本时使用 `asfa-directive-ledger/v5`；两者均将网络身份、安全策略摘要、待办、tombstone、每会话 `(height,latest)` 检查点、执行回执 `receipts` 与死信 `dead_letters` 以确定性数组表示，v5 另携带完整票账本。CLI 通过 `load_for_registry` 强制快照 `network_name` 与 `policy_hash` 同时等于当前 Registry；旧 v1／v2／v3、无网络或无策略身份、跨网络及同网络安全策略变化均不做隐式迁移，加载失败不覆盖原文件。只修改说明性 `role`／`note` 不改变策略摘要，可以继续加载。

策略摘要的域分离定义为：

```text
policy_hash = SHA256(
  "ASFA-OS-XI/REGISTRY-POLICY/V1\n" || serde_json::to_vec(policy_projection)
)
```

`policy_projection` 包含 Registry `schema_version`、`network_name`、`trust_model`，以及每个 session 的读取 URL、解析后的正典 URL、trust、`allow_insecure_http` 和 `allow_file`。`role`／`note` 被明确排除。省略 `canonical_url` 与显式填写相同读取 URL 具有相同投影。该摘要是版本化、确定性的 SHA-256 投影，不是完整 JCS，也不是签名；能同时篡改 Registry 与 state 的本机攻击者仍可重算它。

`save_atomic` 先序列化并拒绝生成超过 16 MiB 的快照，再使用同目录临时文件原子替换。每个候选项都以 `OpenOptions::write(true).create_new(true)` 独占创建：预置 symlink、hardlink、普通文件或 dangling link 均只产生 `AlreadyExists` 冲突，不跟随、不截断、不改名；最多尝试 128 个候选，其他 I/O 错误立即返回，写入与清理错误显式上报。恢复时校验 schema、重复／未知 JSON 成员、重复结构化键、非法指令、非法／重复检查点、“已消费但仍待办”矛盾、回执／死信自身摘要、输出摘要、结果对应 consumed 及同键成功／失败冲突，并执行本地基数上限。恢复后重放仍返回 `Consumed`，历史分叉仍被拒绝。`create_new` 只关闭预置临时项攻击，不防止临时项成功创建后、rename 前遭恶意替换；该原子替换尚未增加 fsync，不声称覆盖掉电持久性。

检查点规则：新高度低于旧高度为 `Rollback`；同高不同 latest 为 `Fork`；更高高度在旧高度处的块哈希必须等于旧 latest，否则为 `Fork`。合法重读和保留旧前缀的延长放行。该检查是 O(n) 全链前缀对拍，不是 Merkle consistency proof；整份状态文件被替换仍需外部单调锚或独立 witness。持久化不是隐式副作用：调用方必须在状态变更后保存，否则重启只恢复到最后一次快照。CLI 在加载前把状态路径解析为实际目标，取得其 `<resolved-state>.lock` sidecar OS 排他锁并持有到输出结束，锁竞争返回非零；最终状态路径符号链接别名因此与同一路径竞争同一把锁。sidecar 自身先经 `symlink_metadata` 检查，预置最终或 dangling lock symlink 均在轮询、消费、状态变化和报告前显式失败；Unix 的实际 open 另加 `O_NOFOLLOW`，避免只依赖 check/open 预检。常规 sidecar 不随状态原子 rename 换 inode；预置 hardlink sidecar 也继续锁住原 inode，而不是迁移到替换后的 state。所有 `--state`、`--out`、`--wave-out`、`--execution-out`、`--ticket-out` 在取锁前统一做目标预检：已存在路径完整 canonicalize；尚未创建的输出解析最深已存在祖先并跟随各层 dangling symlink；解析后同路径即拒绝。既有输出还以 Unix device/inode 或 Windows volume/file index 判重，因而硬链接不能用不同名称绕过。该机制只约束协作 CLI，不能消除验证后恶意改名的 TOCTOU 或取得锁后的 lock pathname 替换，也不提供跨进程硬链接通用锁、非协作写者防护或跨主机锁；非 Unix 的 check/open 竞态不作已关闭声称。

## 5. CLI 入库与消费闭环

CLI 使用的 `poll_registry_detailed_with_deadline` 只在传输、严格 JSON、schema、trust 和完整哈希链全部通过时返回 `Outbox`，并在统一墙钟预算内完成全部会话。`ingest_outbox` 在修改账本前再次执行完整验证和本地检查点对拍，随后在克隆的暂存账本逐条执行并检查容量；任一伪造指令、链头冲突或容量超限都会丢弃整个暂存批次，原账本不变。只有全部成功才一次性替换内存账本并生成 `IngestionEvent`。

```text
StateLock.acquire(<state>.lock)
  → load_for_registry_with_limits(--state, network_name + policy_hash + local caps)
  → poll_registry_detailed_with_deadline（逐请求剩余时间＋会话间 deadline）
  → ingest_outbox（完整复验＋链头对拍＋暂存账本容量门禁）
  → 可选 consume(session, id)
  → 可选 plan_wave（只读）
  → 可选 Mint／Transfer／Revoke（控制票与工作票分离；失败零提交）
  → 执行模式：先保存已复核的原计划，再于克隆账本暂存 execute_wave／execute_ticketed_wave
  → deadline 复核
  → save_atomic(--state, 无票 v4／非空票账本 v5；create_new 独占临时项，≤128 冲突重试)
  → 输出 BridgeReport.ingestion / qfos-wave-plan/v1 / qfos-wave-execution/v1 / asfa-ticket-operation/v1
```

`--consume-session` 与 `--consume-id` 必须成对提供，且消费必须同时指定 `--state`；`--state`、`--out`、`--wave-out` 与 `--execution-out` 不得指向同一解析路径或既有文件身份，冲突在锁、轮询、执行和任何输出前以 `output path alias` 非零失败。状态文件不存在时从空账本开始，存在但无法解析或恢复矛盾时直接失败，不覆盖原文件。`state_saved=true` 只表示本次原子保存已返回成功，不表示收到外部 ACK。

`ingestion` 汇总 `inserted`、`duplicate`、`replayed_consumed`、`conflict`、`expired`、`invalid`、`chain_checkpoints`、`pending`、`tombstones` 和逐指令事件；`chain_checkpoints` 统计完成本地一致性对拍并提交的会话检查点次数。`--fail-on-error` 将轮询失败、`conflict`、`invalid`、消费 `not_found` 以及新产生或恢复的执行死信转为非零退出；`duplicate`、`replayed_consumed` 与入库阶段的 `expired` 是已显式分类的协议结果，不单独触发该门禁。

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

### 5.2 仓内受控执行契约 `qfos-exec-v1`

`--execute-wave` 必须同时提供 `--state`、`--wave-out` 与 `--execution-out`，四者路径不得冲突。若计划文件已存在，CLI 严格读取并复核 schema、mode、逐 Job 与来源计数和 `plan_hash`，随后恢复原计划；不存在时才生成新计划。执行模式在任何结果可能消费 pending 之前先保存原计划，避免“账本已提交而恢复锚点未落盘”的空档。

本契约只允许两个纯内置动作：

| action | 封闭输入与硬上限 | 成功输出 |
|---|---|---|
| `engine.sum` | 仅 `{"values":[i64,...]}`，最多 1024 项，逐项 `checked_add` | `{"count":N,"sum":S}` |
| `engine.sha256` | 仅 `{"text":"UTF-8"}`，最多 1048576 字节 | `{"bytes":N,"sha256":"..."}` |

未知 action、payload schema 错误、输入超限、i64 算术溢出分别形成 `unknown_action`、`invalid_payload`、`input_limit`、`arithmetic_overflow` 死信。计划生成时已过期指令不会入选；已入选计划在执行时发现 `expires_epoch <= now`，形成 `expired` 死信。没有 shell、网络、动态库或外部进程执行路径。

成功回执包含真实 `output`、引擎标识、计划／输入／输出摘要和执行时间；死信包含失败类别、非空消息、计划／输入摘要和失败时间。摘要域分别为：

```text
ASFA-OS-XI/QFOS-EXECUTION-INPUT/V1\n
ASFA-OS-XI/QFOS-EXECUTION-OUTPUT/V1\n
ASFA-OS-XI/QFOS-EXECUTION-RECEIPT/V1\n
ASFA-OS-XI/QFOS-DEAD-LETTER/V1\n
ASFA-OS-XI/QFOS-EXECUTION-REPORT/V1\n
```

每个域后接对应无自哈希字段投影的 `serde_json::to_vec` 字节；输入投影始终包含 `expires_epoch`（无值时为 `null`）。执行报告 `qfos-wave-execution/v1` 另绑定 network、policy、plan、执行时间、逐项结果与汇总计数。所有 SHA-256 都是确定性完整性摘要，不是发布者签名或外部 witness。

`execute_wave` 先在克隆账本完成全部校验、执行和结果提交，任何绑定或容量错误都丢弃暂存账本。成功时，调用者内存账本一次性替换；CLI 再以一次 v4 原子快照保存 pending 删除、consumed tombstone、回执和死信。已有匹配回执／死信只生成 `skipped_succeeded`／`skipped_dead_lettered`，不重跑内置动作、不复制结果；已经 consumed 却没有执行结果的键 fail-closed。状态保存后才写执行报告，因此报告输出失败可用原计划与 v4 结果恢复。该性质是本地、单协作写者边界内的恢复幂等，不是分布式 exactly-once，也不是外部 QF-OS 正典或 QIOS 兼容声称。

### 5.3 一次性任务票与 v5 快照

Mint 同时创建一张由 controller 持有的根控制票和每个计划作业各一张工作票。控制票只用于整根 Revoke；工作票用于 Transfer 和 Execute。两种票均绑定 `plan_hash`，避免“根票既被消费派生子票、又须保留用于撤销”的单次消费冲突。

- Transfer 消费当前工作票并创建同作业、同根、同计划、序列号加一且指定新接收人的子票。
- 每个 `(session,id)` 恰有一个 Mint 基票和一条当前工作票链；链尖是序列号最高者。跨作业父链、多基票、重复 ID、序列断裂和双花均拒绝。
- Revoke 只消费控制票。运行时由根状态派生后代失效；恢复时还要求所有 Transfer／Execute 严格早于根 Revoke。`revoke.created_at_epoch <= descendant.created_at_epoch` 失败关闭，包括相同时间戳。
- 每根默认最多 20 张票，硬上限 64；超过预算的创建不消费父票、不留下交易。
- 多作业整波执行要求全部当前工作票链尖属于同一个 `--ticket-agent`。只转移其中一票不会授权整波执行；当前没有拆波执行接口。

Execute 在同一暂存快照中核对执行计划、当前票链、输入指令和接收人，再写入执行回执／死信、指令 tombstone、工作票消费和 Execute 审计交易。任何错误都不替换调用方账本或磁盘状态。v5 将指令状态、执行结果与票历史放在同一快照；内外 `network_name`／`policy_hash` 必须一致。

无票状态仍序列化为 v4，旧固定夹具字节保持；只有非空票账本启用 v5。v4 携带票字段、v5 缺票、空 v5 票账本均拒绝。恢复还会重建 Execute↔回执／死信绑定，删除执行结果或伪造 tombstone 不能通过。

重放不要求旧工作票仍 live，但必须找到同一历史 Execute 交易，核对 actor、plan 和完整输入集合，并确认原执行回执／死信仍存在且匹配；随后只产生 skipped 结果，不新增票交易，状态字节不变。

票、控制票 plan hash、Execute plan hash 和票账本 policy hash 必须是 64 位小写十六进制 SHA-256。票／交易 ID 使用版本化、域分隔 SHA-256。**这些哈希不是签名、witness、发布者认证或 ZK 证明。**

真实旧新 CLI 差分、独立 Python 判读、自洽伪造拒绝和干净重建证据见 `docs/evidence/ticket-utxo-evidence-manifest-2026-11-21.json`。该证据不声称分布式 exactly-once、hostile writer／OS 防护、跨主机锁、WAL／fsync 掉电持久性、共识或外部结算。文章来源仍为二手技术报告，未获得原始 Kiki 实现。

## 6. 负结果

`http_status`、`blocked_egress`、`transport`、`invalid_json`、`invalid_schema`、`invalid_trust`、`unsupported_trust` 都保留在报告中。非公开目的地址在任何 TCP 连接前形成 `blocked_egress`；重定向、正典 URL 错配、未知字段、未授权 scheme、超限输入、解析失败均不得静默跳过。策略／版本恢复失败发生在轮询之前，因此不生成新报告、不覆盖原状态。全轮询 deadline 是整次 CLI 错误而非降级为普通成功报告；超时发生在状态保存前时不生成报告或新状态。开放 Outbox 字段的深度／节点超限分类为 `invalid_json`，配合 `--fail-on-error` 返回非零。

64 层与 16384 节点是应用自身预算，不再依赖 serde_json 默认递归限制充当安全边界。session 数、pending／tombstone／单 Outbox 基数、输出路径身份预检和协作 CLI 写者锁也已具备门禁；这些仍不能替代验证后路径突变防护、非协作写者隔离、CAS、WAL、分布式协调、底层 DNS 强制取消或进程级内存／CPU／文件描述符隔离。
