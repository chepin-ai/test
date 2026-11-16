# 形式化结构、同构映射与攻击矩阵（2026-11-16）

## 1. 当前绑定的结构

### 1.1 JSON 语义唯一性与封闭协议 schema

对任意输入对象 `o`，其成员名先经 JSON 转义解码，再要求递归唯一：

```text
Unique({k₁:v₁, …, kₙ:vₙ}) ⇔ ∀i,j. decode(kᵢ)=decode(kⱼ) → i=j
                            ∧ ∀i. UniqueValue(vᵢ)
```

`strict_json` 在 schema 转换前执行此检查。Outbox、Registry 和 LedgerSnapshot 共用该入口；因此 `a` 与 `\u0061` 不能作为两个键绕过检查。核心协议结构另用 `deny_unknown_fields`，未知扩展不会被静默解释为安全语义；`mailbox` 与区块 `payload` 是明确开放的数据字段。

同一入口定义 `Depth(root)=1`、子值深度为父值深度加一，并要求 `Depth≤64`；每个容器与标量计一个节点，全文档共享 `Nodes≤16384`，对象键不另计。计数在任何 schema 转换前完成，开放 `mailbox`／`payload` 与 Registry、Snapshot 走同一预算。这些性质不表示数字、键排序和字符串转义已经满足完整 RFC 8785，也不等于进程级内存隔离。

### 1.2 传输授权与正典身份

会话读取地址为 `u`，文档自报地址为 `d`，正典地址为：

```text
c = session.canonical_url.unwrap_or(session.url)
```

验证要求 `d = c`，采用精确字符串对拍。只有显式声明 `canonical_url` 后，只读镜像的 `u` 才允许与 `c` 不同。HTTP 自动重定向关闭，300–399 均为显式负结果，第二跳不请求；默认只接受 HTTPS，`http://` 与 `file://` 分别要求 `allow_insecure_http=true` 与 `allow_file=true`。fragment 和其他 scheme 在 I/O 前拒绝；HTTP(S) 还拒绝缺失 host 与 URL userinfo。

这些检查不执行 URL 语义归一化，不认证镜像或发布者，也不等于完整 SSRF 防护。

### 1.3 网络与安全策略联合隔离

网络 `N`、安全策略投影 `P` 的账本记为 `L_(N,H(P))`。CLI 恢复必须满足：

```text
schema = asfa-directive-ledger/v4
snapshot.network_name = N
snapshot.policy_hash = H(P)
H(P) = SHA256("ASFA-OS-XI/REGISTRY-POLICY/V1\n" || serde_json::to_vec(P))
```

`P` 包含 Registry 的 `schema_version`、`network_name`、`trust_model`，以及每会话的读取 URL、解析后的正典 URL、trust、`allow_insecure_http` 和 `allow_file`；`role`／`note` 被排除。省略 `canonical_url` 与显式填写相同读取 URL 具有相同投影。

旧 v1／v2／v3、跨网络或同网络不同安全策略的状态均不能隐式迁移。物理指令键仍为 `(session,id)`；网络与策略通过相互隔离且经过身份对拍的状态文件绑定。v4 另在同一快照保存成功回执与死信，并在恢复时复核其结果摘要、consumed 对应关系和成功／失败互斥。上述摘要均为确定性 SHA-256，不是签名；能同时修改 Registry 和 state 的本机攻击者仍可重算。

### 1.4 本地历史一致性

每个 session 保存检查点 `H=(h,z)`，其中 `h` 为已见高度，`z` 为该高度块哈希。对已通过当前文档完整验链的新链 `C=(h',z',blocks)`：

```text
h' < h                    ⇒ Rollback
h' = h ∧ z' ≠ z           ⇒ Fork
h' > h ∧ h > 0
  ∧ blocks[h-1].hash ≠ z  ⇒ Fork
其他情况                  ⇒ Accept(H := (h',z'))
```

检查点与指令、tombstone 一同进入原子快照。`ingest_outbox` 的顺序是：完整验链 → 指令来源复验 → 检查点对拍 → 指令入库 → 检查点提交。检查点失败发生在指令循环之前，故该 Outbox 的指令、tombstone 和检查点均不改变。

这只是对完整链进行的 **O(n) 前缀一致性检查**，不是紧凑 Merkle consistency proof；只能发现相对于本机旧视图的异常，不能证明全局唯一历史。

### 1.5 资源边界

Outbox 与 Registry 上限均为 2 MiB，LedgerSnapshot 上限为 16 MiB；文件读取同时检查 metadata 与实际读回字节，HTTP 读取也有响应上限。三类 JSON 入口统一限制 64 层与 16384 个值节点。Registry 会话数硬上限为 64；pending、tombstone 与单 Outbox 指令数分别硬限 4096、16384、1024，CLI 只能调低。入库在暂存账本执行，容量失败整批丢弃；快照恢复和写出也执行基数／字节门禁。单会话 15 秒超时继续保留，CLI 另有默认 60 秒全轮询 deadline；活动 HTTP 请求只获得剩余时间，会话间及保存前复核。进程级内存、CPU 和文件描述符硬隔离仍未关闭。

### 1.6 协作写者互斥与消费容量

对同一词法状态路径 `s`，CLI 在任何状态加载前取得 `s.lock` 的 OS 排他锁，并持有到状态、报告和波次输出结束。竞争返回 `WouldBlock` 和非零退出；锁文件是稳定 sidecar，不因状态原子 rename 改变 inode。消费先检查 tombstone 容量，再删除 pending，因此容量失败不会丢失待办。

这只实现协作进程的单写入者门禁，不是分布式锁；路径别名、非协作写者、跨主机文件系统语义、CAS 和 WAL 不在保证内。

### 1.7 QF-OS 有界波次计划

令 `E(t,T)` 为账本中目标为 `t` 或 `*` 且未过期的指令集合，按 `(session,id)` 排序并以来源分组。选择器按来源轮转，满足：

```text
jobs ≤ max_jobs
∀source. admitted(source) ≤ max_per_source
offered = admitted + deferred_wave_quota + deferred_source_quota
```

计划绑定网络、策略、完整账本快照、目标、时间输入、配额、Job 和来源计数；相同账本与参数产生相同计划字节。生成计划不修改账本，也不执行 action。`plan-only-no-execution` 是能力边界，不允许把 `plan_hash` 解释为引擎执行证明、发布者签名或 QIOS 兼容证书。

## 2. 规范同构与真实覆盖边界

| 外部结构 | 可映射性质 | 本仓对应实现与测试 | 没有获得的外部保证 |
|---|---|---|---|
| [RFC 7493 I-JSON](https://www.rfc-editor.org/rfc/rfc7493.html)、[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) | 跨解析器输入必须避免歧义；对象成员唯一 | `strict_json`；顶层、嵌套、转义同名键、未知字段和 Registry 污染负例 | 完整 JCS 数字格式化、UTF-16 键排序和签名前规范字节 |
| [TUF 规范](https://theupdateframework.github.io/specification/latest/) | rollback、freeze、mix-and-match 防护需要版本／网络／策略／过期边界 | 链高单调、旧前缀对拍、网络＋策略摘要绑定、既有过期复核 | 签名 root、角色阈值、可信时钟和外部元数据版本锚 |
| [RFC 9162 CT v2](https://www.rfc-editor.org/rfc/rfc9162.html) | inclusion 与 consistency 是不同证明；checkpoint 是信任锚 | 当前文档逐块 inclusion 式重算；跨轮询旧头一致性检查 | Merkle inclusion/consistency proof、Signed Tree Head、日志签名 |
| [RFC 9942 SCITT 架构](https://www.rfc-editor.org/rfc/rfc9942.html)、[RFC 9943 SCITT VDS](https://www.rfc-editor.org/rfc/rfc9943.html) | append-only、non-equivocation、replayability 分层 | 本地追加一致性与可重放验证 | Signed Statement、Receipt、Transparent Statement、独立 Transparency Service |
| [C2SP tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md) | witness 保存旧 checkpoint，验证新旧一致性后才更新 | 本地 `(height,latest)` 对拍与原子快照 | 独立 witness、签名与 cosignature、并发原子更新、分裂视图抑制 |
| [C2SP tlog-policy](https://github.com/C2SP/C2SP/blob/main/tlog-policy.md) | log／witness／quorum 是显式信任策略 | 当前只能表达“无 witness 的本地模式” | quorum；不能把 `quorum none` 包装成分裂视图防护 |
| [A2A 官方规范](https://github.com/a2aproject/A2A/blob/main/docs/specification.md) | Agent Card 可选 JWS；签名前使用 JCS；每次操作需要授权边界；Webhook 需要 SSRF 与重放考虑 | 正典 URL、传输授权、禁重定向与来源字段对拍提供局部协议映射 | 本仓不是 A2A 实现，没有 Agent Card、JWS、任务授权、完整 SSRF 或 Webhook 安全模块 |
| [OWASP API4:2023](https://owasp.org/API-Security/editions/2023/en/0xa4-unrestricted-resource-consumption/) | 执行超时、批操作数、记录数、内存与存储都需限制 | 文档／快照字节、JSON 深度／节点、64 会话、账本基数、全轮询 deadline 与逐请求剩余时间 | 进程级内存／CPU／文件描述符硬隔离与动态费率策略 |
| [Azure Queue-Based Load Leveling](https://learn.microsoft.com/en-us/azure/architecture/patterns/queue-based-load-leveling)、[Competing Consumers](https://learn.microsoft.com/en-us/azure/architecture/patterns/competing-consumers) | 持续生产快于消费时须容量决策；消费者应幂等并处理 poison message | 有界账本、显式容量失败、消费 tombstone、冲突／非法事件分类；`qfos-exec-v1` 本地原子回执／死信与重放跳过 | 持久 broker、租约、delivery count、分布式死信队列与跨进程消费者协调 |

C2SP 链接是 `main` 开发版，不称为稳定标准。A2A 签名 Agent Card 也只能证明相应卡片的签名完整性，不能自动证明后续任务、指令或履约结果可信。

前沿研究线索：[Signed but Not Safe: Requirement Integrity in Multi-Agent LLM Handoffs](https://arxiv.org/abs/2611.07483) 将问题进一步推进到“交接任务要求是否完整”。本仓尚未实现逐条 requirement 签名、授权范围证明或任务级语义完整性，不能把该论文列为已复现成果。

## 3. 攻击—实现—证据矩阵

### 3.1 既有解析、隔离与链历史门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化对应 |
|---|---|---|
| 顶层重复 `session` | schema 和链处理前返回 `invalid_json` | `duplicate_json_members_are_rejected_before_schema_or_chain_processing` |
| 区块指令内重复 `action` | 不允许不同解析器选择 Harm／Ping 两种语义 | 同上 |
| `a` 与 `\u0061` | 解码后判重并拒绝 | `strict_json::tests::rejects_duplicate_members_at_every_depth`；Python oracle `escaped_duplicate_member` |
| Registry 重复 `network_name` | CLI 非零退出，不创建 state／report | `cli_duplicate_registry_member_does_not_create_state` |
| Snapshot 重复字段 | `InvalidData`，不恢复 | `snapshot_parser_rejects_duplicate_members` |
| 网络 B 复用网络 A 的 state | 网络对拍失败，原 state 字节不变，不生成新报告 | `cli_cross_network_state_reuse_fails_without_overwrite` |
| 合法同链重读／延长 | 重读为 Duplicate；延长保留旧前缀并入新指令 | `checkpoints_accept_extension_and_reject_rollback_and_forks_without_mutation` |
| 新链高度低于旧高度 | `Rollback`，指令与检查点不变 | 同上 |
| 同高不同 latest | `Fork`，无部分应用 | 同上 |
| 更高链但改写旧高度块 | `Fork`，不能借“更长”绕过 | 同上 |
| 重启后遇到分叉 | v4 快照恢复检查点后仍拒绝 | 同上，实际 `save_atomic`＋`load_for_registry` |
| 后续区块伪造来源 | 整份 Outbox 零入库，检查点也为零 | `ingest_outbox_does_not_partially_apply_a_later_forged_block` |
| 跨语言摘要／Unicode 对应 | Python 生成向量由 Rust 接受；Python 独立复算同一向量 | `python_generated_non_ascii_chain_verifies_in_rust`；`scripts/verify-outbox-python.py` |

### 3.2 本轮新增传输、策略与资源门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化对应 |
|---|---|---|
| 302 指向第二跳 | 返回 `http_status=302`，目标服务器命中数为 0 | `redirects_are_explicit_failures_and_never_reach_the_second_hop` |
| 镜像文档伪造正典 URL | `invalid_trust`，明确报告 expected／document 正典 mismatch | `outbox_url_must_match_the_declared_canonical_url` |
| 未授权 HTTP／file／其他 scheme | 在任何文件或 socket I/O 前失败 | `insecure_transports_require_explicit_opt_in_before_io` |
| 未知 Outbox／Registry／Snapshot 字段 | `invalid_schema` 或恢复失败，不静默忽略 | `unknown_protocol_fields_are_rejected_instead_of_silently_ignored` |
| 同网络替换 URL、canonical、trust 或传输授权 | v4 `policy_hash` 对拍失败，state 不变且不生成新报告 | `policy_digest_binds_security_fields_and_excludes_descriptions`；`cli_same_network_policy_change_preserves_state_but_description_change_is_compatible` |
| 只改 `role`／`note` | 策略摘要不变，原 state 可继续加载 | 同上 |
| v2 状态直接交给新 CLI | 先报 `unsupported ledger schema`，不做字段补全式迁移 | `cli_v2_snapshot_is_not_implicitly_migrated` |
| Registry 超过 2 MiB | 轮询前非零失败，state／report 均不创建 | `cli_oversized_registry_fails_before_state_or_report_creation` |
| 文件读取期间增长绕过 metadata | 实际读回超过上限仍失败 | `strict_json::tests::bounded_file_reader_rejects_oversize_input` |
| 64／65 层精确边界与跨分支节点洪泛 | 应用级预算失败关闭，不依赖解析器默认递归限制 | `strict_json::tests::exact_default_depth_boundary_is_enforced`、`exact_default_node_boundary_is_enforced`、`node_budget_is_shared_across_branches` |
| Rust／Python 策略投影漂移 | 独立 Python 从原始 Registry 重算同一 SHA-256；三项自证通过 | `policy_digest_matches_independent_python_known_answer`；`scripts/verify-policy-python.py` |

### 3.3 2026-11-14 饱和攻击、写者与 QF-OS 门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| 唯一 ID 洪泛超过 pending 上限 | 整批失败，不提交成功前缀，不创建 state／report | `capacity_failures_discard_the_entire_staged_batch`；SAT-01：旧端 pending=5，新端 cap=4 返回 2 且零输出 |
| tombstone 无限增长 | 第 limit+1 次消费失败，pending 不删除，状态字节不变 | `cli_tombstone_capacity_preserves_state_and_pending_job`；SAT-02：旧端 consumed=5，新端 cap=2 后第三消费返回 2 |
| 超基数 snapshot 恢复 | 轮询与输出前失败，原状态不变 | `restore_enforces_local_cardinality_limits`；SAT-03 通过 |
| 65 会话扇出 | 任何 socket I/O 前失败 | `cli_registry_fanout_fails_before_transport_or_outputs`；SAT-04：旧端 65 次命中，新端 0 次 |
| 两 CLI 消费不同 ID | 协作写者竞争必须失败关闭；显式重试后不得丢 tombstone | LCK-01：旧端双成功但只剩 1 个 tombstone；新端竞争者返回 2、零网络命中，重试后 consumed=2 |
| 单来源垄断波次 | 来源轮转、双配额和 deferred 守恒；计划不改账本 | `wave_is_fair_bounded_deterministic_and_non_mutating`；`cli_wave_plan_is_deterministic_fair_and_state_bound` |
| 篡改 Job 或账本绑定 | 独立 Python 从原始 snapshot 重建并拒绝 | `scripts/verify-wave-python.py` 两项自证负例；当前 v4 静态计划 `5b27a806…ca34` |
| 把 plan_hash 当执行或 QIOS 证明 | 计划 schema 固定 `plan-only-no-execution`；执行结果必须使用独立报告 | WAVE-03；`qfos-wave-execution/v1` 分离；QIOS 正典定义未解析，无适配器声称 |

预注册与原始结果分别见 `evidence/qfos-fusion-preregister-2026-11-14.json` 和 `evidence/differential-2026-11-14.json`。PASS 只覆盖预注册差分，不证明非协作写者、分布式锁或下游引擎安全。

### 3.4 2026-11-14 全轮询与 JSON 资源预算门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| 首会话延迟耗尽总预算 | 活动请求按剩余时间收缩；第二会话零请求；无成功报告 | `whole_poll_deadline_shrinks_the_active_request`、`cli_whole_poll_deadline_prevents_later_transport_and_report`；TIME-01：旧端两跳均 verified，新端约 44ms 非零退出 |
| 缺值、零、非数字或超过 60 秒 | Registry／网络 I/O 前拒绝 | `cli_poll_timeout_flag_requires_a_bounded_value`；TIME-02 四组负例 |
| 开放 mailbox 深度超过 64 | `invalid_json` 深度错误，不作 verified | `cli_json_depth_and_node_budgets_reject_open_outbox_payloads`；JSON-01 旧端 verified、新端拒绝 |
| 全文档节点超过 16384 | 共享计数器在第 16385 个值拒绝 | 精确边界单元测试；JSON-02 旧端 verified、新端拒绝 |
| Registry／Snapshot 绕过 | 与 Outbox 使用同一严格入口；恢复失败不覆盖状态 | `cli_json_budget_also_covers_registry_and_snapshot_restore`；JSON-03 旧端接受深层 Snapshot，新端轮询前拒绝且字节不变 |

预注册与原始结果见 `evidence/resource-budget-preregister-2026-11-14.json`、`evidence/resource-budget-differential-2026-11-14.json`。独立 `verify-json-budget-python.py` 以迭代遍历复算深度与节点并执行五个已知答案自证。首轮攻击夹具因 genesis 字段错误得到 FAIL，已公开记录并修正重跑；该 FAIL 不计为实现通过。

### 3.5 2026-11-16 `qfos-exec-v1` 受控执行与恢复门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| 把占位 action 当真实执行 | `engine.sum`／`engine.sha256` 必须产生独立可复算输出；pending、consumed、回执一致 | EXE-01；`execution_fixture_replays_exact_known_answers`；固定计划 `f64a8bcc…254a` |
| shell／未知动作、非法 payload、输入洪泛、i64 溢出、计划后过期 | 不进入外部进程；五类失败均显式死信且只消费一次 | EXE-02；`builtins_dead_letters_and_replay_are_real_and_idempotent`；7 项夹具为 2 回执＋5 死信 |
| 执行中途容量失败 | 克隆账本全部丢弃，调用者原 snapshot 不变，不能留下成功前缀 | `capacity_failure_leaves_the_caller_ledger_byte_for_byte_equivalent` |
| consumed 无结果、篡改计划 | fail-closed，不得静默跳过或部分提交 | `consumed_without_an_outcome_fails_closed_without_mutation`；计划负例 |
| 执行报告输出失败 | 原计划先于结果落盘；v4 状态已保存；随后恢复为 skipped，不重复执行 | `cli_fresh_execution_persists_recovery_plan_before_report_output`；`cli_execution_dead_letters_and_report_failure_resume_without_reexecution` |
| 重放同一计划 | 不新增回执／死信，不重复执行，账本字节不变 | EXE-03；真实进程 replay 为 0 新成功、0 新死信、2＋5 skipped |
| 篡改输出／失败类别后重新计算哈希 | 外层摘要合法仍不够，独立 Python 必须从内建语义拒绝 | EXE-04；`verify-execution-python.py` 五项自证含两个 rehashed 假语义样本 |
| v3 隐式迁移、回执／死信矛盾 | 明确拒绝且原文件不变；恢复时复核自身摘要、consumed 和结果冲突 | EXE-05；`v3_snapshot_is_rejected_without_implicit_migration_or_file_mutation` |
| 旧版被误报为已有执行能力 | 同源旧端无执行参数且 7 项 pending；新端产生真实结果 | EXE-06；`evidence/execution-differential-2026-11-16.json` 九项检查全部通过 |

预登记见 `evidence/execution-preregister-2026-11-16.json`，旧新真实进程原始结果见 `evidence/execution-differential-2026-11-16.json`。PASS 仅覆盖本仓 `qfos-exec-v1`，不证明外部 QF-OS 正典、QIOS、通用 Skill 沙箱、分布式 exactly-once、发布者认证或掉电持久性。

## 4. JCS 候选包评估与不采用结论

检索到 `serde_jcs 0.2.0`、`jcs-canonicalize 0.2.1`、`serde_json_canonicalizer 0.4.1`。目前只评估，没有把任何候选加入本仓依赖。

独立运行 `jcs-canonicalize 0.2.1` 自带测试，14 项通过，包括其 vendored Cyberphone 参考语料、非 BMP 键的 UTF-16 排序和 ECMAScript 数字边界。该结果只证明候选包自身测试通过，不证明与本仓 V1 兼容。

不直接替换 `payload_digest` 的原因：

1. 当前 V1 哈希域和既有公开文档必须先保持兼容，不能在原域名下静默改变字节语义。
2. 候选包文档明确说明重复键采用 last-value-wins，仍需本仓的严格前置门禁。
3. 候选包文档明确说明超出 double 精确整数范围的输入会舍入；本仓含 `u64` 时间戳、nonce 和过期字段，不能接受静默舍入。
4. 完整升级需要版本化 V2 哈希域、双实现官方向量、边界值拒绝策略和旧链重验矩阵，而不是增加一个依赖就宣布完成。

## 5. 仍未关闭的攻击面与后续债

1. **DNS 与连接层 SSRF**：DNS rebinding／pinning、解析器意见不一致、连接时 IP 绑定尚未实现；解析过程也不一定受单会话总 timeout 中断。
2. **地址与出口策略**：私网、loopback、link-local、cloud metadata 等地址没有应用层分类拒绝，仍需外层 egress 隔离；禁重定向和默认 HTTPS 不等于完整 SSRF 防护。
3. **进程级资源隔离**：64 会话、全轮询 deadline、逐请求剩余时间、JSON 深度／节点与账本基数已限；进程级内存、CPU、文件描述符硬隔离和动态费率策略未实现，DNS 解析也不因本轮门禁而被证明完整受控。
4. **多写者协调**：协作 CLI 的 sidecar 排他锁已实测；路径别名、非协作写者、跨主机语义、CAS、WAL 和原子 check-and-persist 未实现，不能称为分布式单写者。
5. **整份快照回滚与分裂视图**：攻击者若能同时替换 state 和旧链，本地检查点与策略摘要也会回到旧值。需要外部单调计数器、签名 checkpoint、独立 witness／quorum 及并发原子更新。
6. **发布者与指令授权**：无签名链不认证发布者；后续可映射 A2A/JWS 或 SCITT Signed Statement，但签名对象必须覆盖指令及授权范围，而非只签 Agent Card。
7. **可信时间**：`--now` 是可测试的本地输入，不是可信时间源；过期检查不能替代 TUF 式签名根和时间策略。
8. **完整 JCS V2**：需先确定整数范围和跨语言规范字节，不可沿用 V1 哈希域。
9. **紧凑证明与后量子 witness**：Merkle consistency proof、witness cosignature、ML-DSA-44 均只属后续研究，不在当前代码路径。
10. **系统级研究目标**：原始 ZK、HoTT、WASM、TEE、完整形式化安全证明和完整 OS 目标不在本轮实现范围。
11. **外部协作状态**：联盟 active、cisvr ACK、KEY-SYNC-01 和旧 PAT 撤销均需独立外部回执，不能由本地测试、outbox 写入或公网 `verified` 推导。
12. **QF-OS／QIOS 下游语义**：当前仓内 `qfos-exec-v1` 只有 `engine.sum` 与 `engine.sha256`，已接入本地原子回执、五类死信和重启跳过；引擎租约、通用 Skill 沙箱、结果签名、跨进程分布式 exactly-once 与外部 QF-OS 正典适配仍未实现。QIOS 定义未解析，适配与兼容性均为零声称。

## 6. 独立判读器范围

`scripts/verify-outbox-python.py` 不用 Rust 中间产物，独立执行 UTF-8／重复键解析、V1 负载摘要、逐块哈希、latest 和指令来源检查，并对已知答案与篡改负例自证。为避免 Python 与 Rust 浮点格式差异，它明确只接受无浮点且整数落在 `serde_json` 整数范围内的 V1 子集；其 canonical bytes **不是 RFC 8785 JCS**。

`scripts/verify-policy-python.py` 独立重建 Registry 安全投影和策略摘要，并自证：说明字段变化不改变摘要、显式默认 canonical 不改变摘要、URL 变化必须改变摘要。它可检查 v4 snapshot 的 `network_name` 与 `policy_hash`，但不验证签名、外部信任或状态文件未被整体替换。

`scripts/verify-json-budget-python.py` 使用独立严格重复键解析与显式栈迭代遍历，复算根深度、最大深度和全文档值节点；对象键不另计。它对 64 层接受、65 层拒绝、16384 节点接受、16385 节点拒绝、跨分支计数和转义重复键进行已知答案自证，不读取 Rust 中间结果，也不证明进程内存上限。

`scripts/verify-wave-python.py` 从 Registry 和原始 snapshot 独立重建分组、过期过滤、来源轮转、双配额、deferred 计数、ledger hash 与 plan hash，并拒绝 Job 篡改和账本绑定篡改。其范围为 qfos-wave-v1 无浮点子集，不是 JCS、发布者认证、执行证明或 QIOS 判读器。

`scripts/verify-execution-python.py` 从 Registry、计划前 snapshot、原计划和执行后 snapshot 独立推导内建动作语义、i64 溢出、输入上限、过期优先级、真实输出及全部输入／输出／回执／死信／报告摘要，并逐项核对报告与最终状态。五项已知答案自证包含重新计算内部及外层哈希后的假 sum、假失败类别和假报告结果，因此不能靠重算摘要绕过。该判读器只覆盖仓内 `qfos-exec-v1` 无浮点子集，不是形式化执行证明、结果签名、外部 QF-OS 正典或 QIOS 判读器。

## 7. 可复算证据入口

- `evidence/execution-consistency-2026-11-17.json`：实现提交、92 项测试、无 `.git` 空 target 干净重建、真实执行与重放、九项旧新差分、五类独立判读和 11 项 artifact 的综合证据。
- `evidence/execution-clean-rebuild-2026-11-17.log`：实现提交归档的完整干净重建输出；`execution-smoke-2026-11-17.json` 与 `execution-smoke-state-2026-11-17.json` 保存对应烟测原始结果。
- `evidence/execution-preregister-2026-11-16.json`：真实执行、五类死信、恢复幂等、独立判读、v4 原子性与旧新差分的实现前判据。
- `evidence/execution-differential-2026-11-16.json`：同一 Registry／Outbox 下旧端无执行能力、新端真实执行与重启跳过的九项进程差分；新端哈希属于工作树 debug 构建，不与后续干净归档哈希混用。
- `evidence/resource-budget-preregister-2026-11-14.json`：全轮询与 JSON 深度／节点攻击的实现前判据。
- `evidence/resource-budget-consistency-2026-11-14.json`：实现提交、85 项测试、干净归档、五组差分、独立 JSON 判读、公网复核和七项 artifact 校验的综合证据。
- `evidence/resource-budget-differential-2026-11-14.json`：TIME-01／02、JSON-01／02／03 的旧新真实进程结果及独立判读。
- `evidence/resource-budget-clean-rebuild-2026-11-14.log`：无 `.git`、空 target 的完整统一门禁重建输出。
- `evidence/json-budget-oracle-2026-11-14.json`：独立 Python 的精确深度／节点边界与五个已知答案自证。
- `evidence/resource-budget-poll-2026-11-14.json`：干净二进制在显式 60 秒总预算下采集的七端点公网报告。
- `evidence/qfos-fusion-preregister-2026-11-14.json`：实现前登记的五项进程攻击与三项波次判据。
- `evidence/attack-consistency-2026-11-14.json`：实现提交、78 项测试、干净归档、五组差分、独立判读和公网复核的综合证据。
- `evidence/differential-2026-11-14.json`：pending、tombstone、恢复、65 会话扇出及并发消费的旧新原始差分。
- `evidence/wave-oracle-2026-11-14.json`：独立波次重建、静态已知答案与两个篡改负例。
- `evidence/poll-2026-11-14.json`：当前实现采集的七端点公网报告。
- `evidence/attack-consistency-2026-11-11.json`：上一轮干净归档、67 项测试、五组旧新 CLI 差分、策略已知答案、公网正典迁移和未覆盖边界。
- `evidence/differential-2026-11-11.json`：五组攻击的旧／新进程级原始结果。
- `evidence/poll-2026-11-11.json`：干净归档产物对七个公网端点的原始轮询报告。
- `evidence/attack-consistency-2026-11-10.json`：上一轮历史证据，保留当时的公网 URL 差异，不回写为本轮结果。
- `../scripts/verify-outbox-python.py`：独立 Python 链判读与已知答案／篡改负例自证入口。
- `../scripts/verify-policy-python.py`：独立 Python 策略投影、fixture 与 live snapshot 对拍入口。
- `../scripts/verify-json-budget-python.py`：独立迭代 JSON 深度／节点判读与已知答案入口。
- `../scripts/verify-wave-python.py`：独立 Python 波次重建、静态已知答案与篡改负例入口。
- `../scripts/verify-execution-python.py`：独立执行语义、状态／报告勾稽、固定夹具与 rehashed 假语义负例入口。
- `../scripts/build-all.sh`：格式、Clippy、全部测试、凭据扫描、五类 Python 判读、认知示例、波次与执行固定夹具字节对拍、执行重放和 CLI 烟测的统一重建门禁。

本轮公网正典已明确迁移到实际发布的 `.../main/...` 形式；当前字节一致只适用于本轮采集时点，不能回改 2026-11-10 的历史差异。镜像 `verified` 也不等于发布者认证。所有外部状态（推送、CI、ACK、正典 active、KEY-SYNC-01）均需要独立回执。
