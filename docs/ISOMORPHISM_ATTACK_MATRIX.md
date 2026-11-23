# 形式化结构、同构映射与攻击矩阵（2026-11-21）

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

这些检查不执行 URL 语义归一化，不认证镜像或发布者。HTTP(S) 目的地址另受默认 public-only 策略约束：令一次策略解析的答案为 `A`，要求 `1≤|A|≤32`，且每个 `a∈A` 都通过地址分类；随后以原 URL 端口构造固定 `SocketAddr` 集 `P`，实际 agent 只能返回 `P`。任一非公开成员使整组失败，因此混合公网／私网答案不能只挑公网成员放行。请求保留原 URL authority 与 TLS server name，禁止环境代理与重定向，避免绕过固定连接目的。

IP 字面量不经过 DNS。域名解析等待受剩余预算约束，超时 worker 不持有 HTTP agent；但底层系统解析的强制取消、阻塞线程回收、外层 egress 隔离和 hostile OS 仍不属于该应用层不变量。显式进程级 `AllowNonPublic` 只用于本地测试／受控遗留部署，不可由 Session JSON 开启。

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

Outbox 与 Registry 上限均为 2 MiB，LedgerSnapshot 上限为 16 MiB；文件读取同时检查 metadata 与实际读回字节，HTTP 读取也有响应上限。三类 JSON 入口统一限制 64 层与 16384 个值节点。Registry 会话数硬上限为 64；pending、tombstone 与单 Outbox 指令数分别硬限 4096、16384、1024，CLI 只能调低。入库在暂存账本执行，容量失败整批丢弃；快照恢复和写出也执行基数／字节门禁。单会话 15 秒超时继续保留，CLI 另有默认 60 秒全轮询 deadline；域名解析等待、活动 HTTP 连接／读／写只获得剩余预算，会话间及保存前复核。DNS 空答案与超 32 答案也失败关闭。进程级内存、CPU、文件描述符和阻塞 resolver 线程的硬隔离仍未关闭。

### 1.6 协作写者互斥与消费容量

对解析后的状态目标 `s=resolve(state)`，CLI 在任何状态加载前取得 `s.lock` 的 OS 排他锁，并持有到状态、报告和波次输出结束；最终符号链接别名与直接路径共享该锁。竞争返回 `WouldBlock` 和非零退出；锁文件是稳定 sidecar，不因状态原子 rename 改变 inode。消费先检查 tombstone 容量，再删除 pending，因此容量失败不会丢失待办。

所有声明输出另在取锁前执行 `resolve` 与既有文件身份判重。该预检覆盖 `..`、符号链接父目录、最终／dangling symlink 与硬链接，但不覆盖验证后恶意改名、跨进程硬链接通用锁、非协作写者、跨主机文件系统语义、CAS 或 WAL；它不是分布式锁。

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

### 3.6 2026-11-17 public-only egress 与 DNS rebinding 门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| URL 直接使用 loopback／私网／metadata | 默认策略在 TCP accept 前返回 `blocked_egress` | EGR-01／02；48 条 Rust＋Python 地址已知答案；旧端 `verified／1 hit`，干净新端 `blocked_egress／0 hit` |
| 域名解析到非公开地址 | 实际 resolver 答案验证失败，不能拨号 | `hostname_resolving_to_loopback_is_blocked_before_any_dial` |
| 混合公网＋非公开答案、空答案、33 个答案 | 整组 fail-closed；答案硬顶 32 | `mixed_answers_and_answer_capacity_fail_closed` |
| 验证后第二次 DNS rebinding | 策略解析恰好一次；实际 agent 只拨已验证地址，原 Host 保留 | `validated_resolution_is_the_only_resolution_and_the_actual_dial_target`：A 收到请求、B 零命中、`Host: pinned.test:<port>` |
| 代理环境变量绕过固定目的 | 显式本地放权仍不得使用环境代理 | EGR-04 进程差分：六类代理变量同时注入，target=1、proxy=0、verified |
| 不可信 Session／Registry 私加放权字段 | `deny_unknown_fields` 拒绝；不能开启非公开 egress | EGR-06：`untrusted_session_json_cannot_enable_non_public_egress`；真实 CLI exit=2、零命中、无报告 |
| 阻塞 resolver 拖死调用方 | 小预算内有界等待；worker 无 HTTP agent | EGR-05：20ms 预算对 250ms resolver；不声称底层 resolver 强制取消或线程资源隔离 |
| 门禁误改 file／链／执行语义 | 既有全部固定夹具、deadline 与重放保持不漂移 | EGR-07：实现提交无 `.git`、空 target 完整重建，99／99 测试和全部独立判读通过 |

预注册、原始旧新进程结果和综合证据分别为 `evidence/egress-preregister-2026-11-17.json`、`evidence/egress-differential-2026-11-17.json`、`evidence/egress-consistency-2026-11-17.json`。首轮 Rust／Python 分类顺序 FAIL 与差分测试器 bytes 编码 FAIL 均保留在综合证据的 `development_corrections`，未计作首轮通过。PASS 只覆盖该 HTTP client 的应用层目的地址门禁，不是 network namespace、外层 egress proxy、hostile OS 防护或通用 SSRF 证明。

### 3.7 2026-11-21 输出路径身份与状态锁别名门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| `state` 与 `sub/../state` 分别作为报告／计划／执行输出 | 取锁、轮询、执行和写入前非零失败 | PATH-01／03：三个旧端 exit=0 并分别把账本覆盖成 report／plan／execution；干净新端 exit=2、零状态变化、零锁文件 |
| dangling 最终 symlink 或符号链接父目录 | 跟随链接实际目标，不存在不等于无别名 | PATH-01／04：两个旧端覆盖状态，新端保留链接且目标不创建 |
| 两个既有输出是同一硬链接 inode | 不仅比较路径字符串，还比较平台文件身份 | PATH-02／04：旧端 wave 覆盖 poll 报告；新端保留两个 sentinel 及共享 device/inode |
| 直接路径与最终 symlink 分别获取状态锁 | 两者必须竞争同一解析目标 sidecar | `final_symlink_alias_contends_for_the_target_lock`：第二次获取为 `WouldBlock` |
| 判读器照抄 Rust 结论或接受假报告 | Python 独立 realpath／samefile／stat 并重读文件系统 | PATH-06：五项路径已知答案、五类假报告拒绝、八组差分复核 |
| 正常不同输出与既有固定锚点 | 不得把安全修复变成语义漂移 | PATH-05／07：distinct control 旧新产物字节相等；104 项测试与固定 wave／execution／replay 哈希不漂移 |

预注册、原始差分、综合证据与干净重建日志分别为 `evidence/path-preregister-2026-11-21.json`、`evidence/path-differential-2026-11-21.json`、`evidence/path-consistency-2026-11-21.json`、`evidence/path-clean-rebuild-2026-11-21.log`。首轮 dangling symlink 实现 FAIL 和判读器 hardlink 标签 FAIL 均公开保留。PASS 不覆盖验证后恶意改名、跨进程硬链接通用锁、非协作写者、分布式协调或掉电持久性。

### 3.8 2026-11-21 账本临时项独占分配与有界耗尽门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| 预置可预测临时 symlink／hardlink 指向 victim | 不得跟随、截断或把 victim 身份改名成 state | ATOMIC-01／02：旧端 exit=0、victim 被覆盖且 state 成为链接或共享 inode；新端经其他候选 exit=0，victim 与首项链接不变，state 为独立常规文件 |
| 预置普通临时文件 | 不得覆盖或改名既有文件 | ATOMIC-03：旧端覆盖并改名首项；新端保留 sentinel 原名与字节，state 与正常控制相等 |
| 128 个连续候选均被占用 | 必须有界失败且保留全部冲突项 | ATOMIC-04：新端 exit=2、无 state、128 个 sentinel 全部保留并给出耗尽诊断；旧端仍覆盖并改名首项 |
| 判读器照抄退出码或伪造 after-state | 从真实 PID 重建临时名并重读当前文件系统 | ATOMIC-05：四项文件系统已知答案和五类假报告拒绝先于五组真实报告验收 |
| 正常保存、固定锚点或干净重建漂移 | 正常控制字节相等，完整门禁不漂移 | ATOMIC-06／07：旧新控制 state 字节相等；106 项测试、八类独立判读及 wave／execution／replay／path 锚点通过；最终差分使用无 `.git`、空 target 的干净归档二进制 |

预注册、原始差分、综合证据与干净重建日志分别为 `evidence/atomic-write-preregister-2026-11-21.json`、`evidence/atomic-write-differential-2026-11-21.json`、`evidence/atomic-write-consistency-2026-11-21.json`、`evidence/atomic-write-clean-rebuild-2026-11-21.log`。首次 PoC 的 Python `with_extension` 夹具错误没有执行目标进程，修正为 `with_suffix` 后才确认旧端漏洞；state-lock sidecar 候选未包装成锁互斥突破。PASS 只关闭预置临时项攻击，不覆盖创建后至 rename 前的恶意替换、hostile OS、非协作写者、WAL／fsync、掉电持久性或分布式事务。

### 3.9 2026-11-21 state-lock symlink 与跨 rename inode 迁移门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| 预置 `<state>.lock -> state.json`，首进程在 rename 后阻断于 FIFO | 不得让第二进程在首进程存活时经 symlink 锁到替换后的 state inode | LOCK-01／02：旧端第二进程 exit=0、pending/consumed=5/1；新端两个进程均 exit=2、状态字节与 inode 不变、FIFO 零字节 |
| 预置 dangling lock symlink | 不得跟随链接、创建缺失 target 或进入轮询／报告 | LOCK-01：旧端 exit=0 并创建 target；新端 exit=2，target／report 不存在，state 与 symlink 不变 |
| 常规 sidecar 跨 `save_atomic` rename | sidecar 必须继续保持排他，不能随 state 换 inode | LOCK-03：旧新第二进程均 exit=2，首进程仍存活，pending/consumed 保持 6/0 |
| 预置 hardlink sidecar 跨 rename | 继续锁住初始 state inode，不得迁移到替换 inode | `regular_sidecar_excludes_second_writer_after_state_rename` 与真实 hardlink 差分：第二进程 exit=2，lock inode 保持初始值 |
| 只依赖可移植 check/open 预检 | Unix 实际 open 必须同时使用 `O_NOFOLLOW`，其他错误显式返回 | LOCK-04：独立源码判读确认 `custom_flags` 位于 `options.open` 之前；三项新增 state_lock 回归通过 |
| 判读器伪造进程／文件系统结果 | 独立复核 liveness、FIFO、schema、链接目标、inode 和 SHA-256，并先自证 | LOCK-05：五项文件系统已知答案、六类假报告拒绝先于五组真实报告验收 |
| 正常控制与既有锚点漂移 | 控制字节相等；完整门禁和干净重建不得漂移 | LOCK-06／07：109 项 Rust 测试、九类 Python 判读及固定锚点通过；最终差分使用实现提交的干净归档二进制 |

预注册、原始差分、综合证据与干净重建日志分别为 `evidence/lock-symlink-preregister-2026-11-21.json`、`evidence/lock-symlink-differential-2026-11-21.json`、`evidence/lock-symlink-consistency-2026-11-21.json`、`evidence/lock-symlink-clean-rebuild-2026-11-21.log`。夹具和判读器纠偏均公开保留。PASS 不覆盖取得锁后的常规 lock pathname 替换、非 Unix check/open 竞态、非协作写者、hostile OS、跨主机锁、WAL／fsync 或分布式协调。

### 3.10 2026-11-21 一次性任务票与恢复门禁

| 攻击／碰撞 | 预注册拒绝条件 | 自动化与实测对应 |
|---|---|---|
| 无票、他人票、旧票或部分转移后执行 | 只接受全部当前工作票链尖同属执行 agent 的整波 | `missing_ticket`、`transfer_lineage`：真实 CLI 失败关闭；只转移七票之一不授权整波，当前无拆波接口 |
| 跨作业父链、双基票、重复 ID、序列断裂或双花 | 每作业恰一基票和唯一当前链，spent／血缘完整重建 | Rust 单元、恢复负例与 `corrupt_snapshot_rejection` 原始快照由独立 Python 亲自拒绝 |
| 根撤销后伪造 Transfer／Execute 历史 | 派生交易必须严格早于根 Revoke；相同时间也拒绝 | `post_revoke_execution`：Revoke=50、Execute=100 的自洽伪造状态被 Rust exit 2 与 Python 同时拒绝；另有 Rust Transfer 回归 |
| 根预算耗尽 | 第 21 票不得消费父票或留下交易 | `root_budget_20_21`：真实 CLI 有界失败，状态不变 |
| 删除回执／死信后重放 | 必须找到同一历史 Execute、完整输入集合及仍存在的结果 | `mint_execute_replay`：合法重放仅 skipped、v5 字节不变；恢复负例拒绝删除结果 |
| 指令／数据混淆或异计划替换 | 只有指令槽决定 action；票与 Execute 均绑定 plan hash | `instruction_data_isolation`、64 位小写摘要形态与跨计划负例 |
| 判读器照抄 runner verdict | 独立重建 ID、digest、血缘、spent、结果绑定并先自证 | 3 个已知答案、1 个合成有效、4 个合成拒绝；伪造真实报告在验收前拒绝 |
| 固定夹具或干净重建漂移 | 无票 v4 字节保持；从实现归档完整重跑 | 118 项 Rust 测试、完整 `build-all`、9 组／48 进程差分与最终 v5 状态 PASS |

预登记、最终差分、独立判读和总索引分别为 `docs/evidence/ticket-utxo-preregister-2026-11-21.json`、`docs/evidence/ticket-utxo-differential-2026-11-21.json`、`docs/evidence/ticket-utxo-consistency-2026-11-21.json`、`docs/evidence/ticket-utxo-evidence-manifest-2026-11-21.json`。原预登记旧二进制因环境重置未参与最终差分；最终旧端从同一基线提交重建，哈希差异已登记。PASS 不覆盖分布式 exactly-once、发布者认证、hostile writer／OS、共识、外部结算、签名 witness 或 ZK 证明。

### 3.11 2026-11-23 旧执行与票变更组合门禁

| 攻击／碰撞 | 登记拒绝条件 | 自动化与实测对应 |
|---|---|---|
| Transfer-self＋旧 Execute 留下无 Execute 的结果历史 | 新端在任何运行时副作用前拒绝执行＋票变更组合 | 旧端 exit 0，写入 2 个 receipt、5 个 dead letter 和 Transfer；新端 exit 2，Mint 状态字节不变且所有声明输出不存在 |
| Revoke＋旧 Execute 形成根失活混合态 | 同上，不得先执行再撤销或先撤销再执行 | 旧端复现混合历史；新端拒绝，随后正常 ticketed Execute／Replay 通过 |
| 将单独旧执行误报为本轮漏洞 | 无票变更的旧接口仍须字节兼容 | v4 旧新控制字节相等；拒绝范围严格限定为同一调用中的组合 |
| Transfer 混合态被夸大为永久丢失 | 保留反例并缩小结论 | 晚时间戳恢复失败，但原结果时间戳可吸收并补记 Execute；`ANOMALY-1` 明示不是永久丢失 |
| runner 自报 PASS 或伪造历史混入 | 独立判读、自证、真实状态重验与伪造报告拒绝 | 5 组、17 个真实进程步骤；独立 PASS，伪造真实报告在验收前被拒绝 |

实现提交为 `88e01c894b88773fe5a5f89bac54b285c9d02f1c`，只改变 CLI 组合校验及其验证。探索后预注册保持 `AFTER_EXPLORATORY_REPRO_BEFORE_FIX`；最终新端来自该提交归档的无 `.git`、空 target 重建。完整门禁为 119 项 Rust 测试及既有独立判读、固定夹具和 smoke。证据总索引为 `docs/evidence/ticket-mixed-mode-evidence-manifest-2026-11-23.json`。

### 3.12 2026-11-23 Lean 证据联邦与跨基座投影门禁

| 攻击／碰撞 | 登记拒绝条件 | 自动化与实测对应 |
|---|---|---|
| coupling／bridging 经闭包升级为传递关系 | 无显式组合规则即失败 | Lean `coupling_not_transitive`、`bridging_not_transitive`；独立 Python 8 个关系已知答案 |
| lossy 图谱／复形／超图／范畴／LaTeX 投影升格 FORMAL | 只有 canonical JSON 精确投影保持 R1，其余均为 CANDIDATE＋反向重放义务 | 6 声明×6 基座共 36 投影逐项复核；Lean 与 Python 均拒绝 FORMAL 升格 |
| 同逻辑键异命题覆盖 | 整批 `statementConflict`，registry 字节不变 | Lean 冲突定理＋真实同步负控；独立判读亲自构造哈希已修复的语义冲突 |
| 新环境改写原生产者 | 同键同命题只追加 attestation，幂等重放不变 | Lean 来源保持定理；合成双环境、双 origin 和重放已知答案 |
| runner 自报证明或哈希修复伪造 | 独立源树、#check、axiom、registry、projection 重建并先自证 | 2 个合成有效、4 个合成拒绝、3 个投影边界；伪造真实报告验收前拒绝 |
| 普通构建冒充沙箱／多内核／跨机 | R1 与 R2 严格分层 | `lake check` 在 bwrap 初始化失败即记 `NOT_ESTABLISHED`，未使用非隔离绕行 |

实现提交为 `280d62f3e2225ac7ea314b4492aa51d78a32f6a8`。当前仅本线 `FORMAL_R1`；usrm legacy 包未激活，跨线 ACK、外部 CI 和全局统一不成立。总索引为 `docs/evidence/lean-federation-evidence-manifest-2026-11-23.json`。

## 4. JCS 候选包评估与不采用结论

检索到 `serde_jcs 0.2.0`、`jcs-canonicalize 0.2.1`、`serde_json_canonicalizer 0.4.1`。目前只评估，没有把任何候选加入本仓依赖。

独立运行 `jcs-canonicalize 0.2.1` 自带测试，14 项通过，包括其 vendored Cyberphone 参考语料、非 BMP 键的 UTF-16 排序和 ECMAScript 数字边界。该结果只证明候选包自身测试通过，不证明与本仓 V1 兼容。

不直接替换 `payload_digest` 的原因：

1. 当前 V1 哈希域和既有公开文档必须先保持兼容，不能在原域名下静默改变字节语义。
2. 候选包文档明确说明重复键采用 last-value-wins，仍需本仓的严格前置门禁。
3. 候选包文档明确说明超出 double 精确整数范围的输入会舍入；本仓含 `u64` 时间戳、nonce 和过期字段，不能接受静默舍入。
4. 完整升级需要版本化 V2 哈希域、双实现官方向量、边界值拒绝策略和旧链重验矩阵，而不是增加一个依赖就宣布完成。

## 5. 仍未关闭的攻击面与后续债

1. **出口策略的进程外边界**：本 HTTP client 已有 public-only 分类、完整答案验证、单次策略解析和连接固定；其他进程、其他协议与非协作代码仍可自行拨号。network namespace、外层 egress proxy、hostile OS 与通用 SSRF 防护仍需独立机制。
2. **DNS 取消与线程生命周期**：解析等待超时只释放调用方，worker 不持有 HTTP agent；底层系统 resolver 是否取消、阻塞线程何时退出及其资源消耗没有被强制隔离。地址表也是显式保守策略，不声称替代完整 IANA 注册表或外部威胁情报。
3. **进程级资源隔离**：64 会话、全轮询 deadline、逐请求剩余时间、JSON 深度／节点与账本基数已限；进程级内存、CPU、文件描述符硬隔离和动态费率策略未实现，DNS 阻塞 worker 也未获得独立资源域。
4. **多写者协调与原子写剩余竞态**：输出路径解析／文件身份预检、最终状态路径 symlink 锁汇聚、预置 lock symlink 拒绝＋Unix `O_NOFOLLOW`、常规／hardlink sidecar 跨 rename 排他和账本临时项 `create_new` 独占分配已实测；验证后恶意改名、取得锁后的常规 lock pathname 替换、临时项创建后至 rename 前的恶意替换、非 Unix check/open 竞态、跨进程硬链接通用锁、非协作写者、跨主机语义、CAS、WAL 和原子 check-and-persist 未实现，不能称为分布式单写者。
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

`scripts/verify-egress-python.py` 使用 Python `ipaddress` 与独立 CIDR 表重算 48 条预注册 IPv4／IPv6 分类，不读取 Rust 分类输出。它还独立检查 blocked 报告的汇总、单记录、`blocked_egress` 状态、loopback 原因与 TCP hits=0，并以错误状态、伪造 verified 汇总、实际发生连接和额外记录四类已知答案假报告自证。该判读不证明 network namespace、底层 DNS 取消或通用 SSRF 防护。

`scripts/verify-path-python.py` 独立使用 `realpath`、`samefile` 与 `stat` 判定路径／硬链接身份，重读每个差分 after-state，并核对旧端实际覆盖、新端零写入、锁未创建和正常控制产物相等。五项路径已知答案与五类假报告自证先于真实报告判读；它不证明预检后的路径名不会被敌对并发修改。

`scripts/verify-atomic-write-python.py` 从记录的真实子进程 PID 独立重建临时路径，以 `lstat` 等价状态、`stat`、SHA-256、严格 JSON schema、链接目标和文件身份复核五组旧新报告及当前磁盘。四项 regular／symlink／hardlink／absent 已知答案与 old failure、old without damage、new victim changed、new state symlink、new collision removed 五类假报告拒绝先于真实报告验收；它不证明临时项创建后至 rename 前的路径名不会被替换。

`scripts/verify-lock-symlink-python.py` 独立复核双进程 liveness、FIFO 字节与 schema、v4 pending/consumed、链接目标、目标／链接 inode 和 SHA-256，并重读最终文件系统与 Unix `O_NOFOLLOW` 源码顺序。五项 regular／symlink／hardlink／FIFO／absent 已知答案和六类假报告拒绝先于真实报告验收；它不证明取锁后常规 lock pathname 不会被替换，也不覆盖非 Unix check/open 竞态。

`scripts/verify-json-budget-python.py` 使用独立严格重复键解析与显式栈迭代遍历，复算根深度、最大深度和全文档值节点；对象键不另计。它对 64 层接受、65 层拒绝、16384 节点接受、16385 节点拒绝、跨分支计数和转义重复键进行已知答案自证，不读取 Rust 中间结果，也不证明进程内存上限。

`scripts/verify-wave-python.py` 从 Registry 和原始 snapshot 独立重建分组、过期过滤、来源轮转、双配额、deferred 计数、ledger hash 与 plan hash，并拒绝 Job 篡改和账本绑定篡改。其范围为 qfos-wave-v1 无浮点子集，不是 JCS、发布者认证、执行证明或 QIOS 判读器。

`scripts/verify-execution-python.py` 从 Registry、计划前 snapshot、原计划和执行后 snapshot 独立推导内建动作语义、i64 溢出、输入上限、过期优先级、真实输出及全部输入／输出／回执／死信／报告摘要，并逐项核对报告与最终状态。五项已知答案自证包含重新计算内部及外层哈希后的假 sum、假失败类别和假报告结果，因此不能靠重算摘要绕过。该判读器只覆盖仓内 `qfos-exec-v1` 无浮点子集，不是形式化执行证明、结果签名、外部 QF-OS 正典或 QIOS 判读器。

`scripts/verify-ticket-utxo-python.py` 不调用 Rust 验证器，独立重建版本化票／交易 ID、票账本 digest、控制票／工作票 plan 绑定、唯一作业链、根序列与预算、spent 集合、Execute↔回执／死信绑定和根撤销时间顺序。它先执行 3 个已知答案、1 个合成有效和 4 个合成拒绝，再亲自拒绝报告内每个伪造快照，并验证真实 9 组／48 进程差分；伪造真实报告在验收前被拒绝。该判读不是签名、发布者认证、ZK、分布式 exactly-once 或 hostile writer 防护证明。

`scripts/verify-ticket-mixed-mode-python.py` 复用上述独立票账本校验但不调用 Rust，另以 5 个混合历史已知答案自证，亲自分类旧端原始快照、核对无 Execute 的结果历史和拒绝前后状态字节，再验收 5 组／17 进程真实报告。它还以语义不符但哈希已同步修正的真实报告变体验证拒绝理由，避免只做哈希对拍；Transfer 原时间戳吸收被作为有效反例核对，而非隐藏。

## 7. 可复算证据入口

- `evidence/ticket-mixed-mode-evidence-manifest-2026-11-23.json`：混合模式实现／基线、探索后登记、干净重建、17 步差分、独立 PASS、异常注记和 artifact 哈希总索引。
- `evidence/ticket-mixed-mode-differential-2026-11-23.json`：旧端 Transfer／Revoke 混合历史、新端副作用前拒绝、正常执行／重放、独立票变更与 v4 控制的真实进程证据。
- `evidence/ticket-mixed-mode-consistency-2026-11-23.json`：独立判读 PASS、混合历史已知答案、自证与伪造真实报告拒绝。
- `../scripts/ticket-mixed-mode-differential.py`：真实旧新 CLI 混合模式 runner；只写 `EXECUTED_AWAITING_INDEPENDENT_ORACLE`，不自行宣称最终 PASS。
- `../scripts/verify-ticket-mixed-mode-python.py`：独立历史分类、原始状态复验、吸收反例和伪造报告反证入口。

- `evidence/ticket-utxo-evidence-manifest-2026-11-21.json`：实现／基线提交、干净重建环境、实际新旧二进制、环境重置注记、最终 PASS 与 artifact 哈希总索引。
- `evidence/ticket-utxo-differential-2026-11-21.json`：九组真实旧新 CLI、48 个进程步骤及原始伪造快照；新端来自无 `.git`、空 target 的实现归档。
- `evidence/ticket-utxo-consistency-2026-11-21.json`：独立判读 PASS，含自证计数、伪造真实报告拒绝和报告哈希。
- `evidence/ticket-utxo-state-verdict-2026-11-21.json`：最终 v5 状态独立 PASS 与票账本哈希。
- `../scripts/ticket-utxo-differential.py`：真实旧新进程、九组攻击／控制与报告生成入口；runner 不自行宣称最终 PASS。
- `../scripts/verify-ticket-utxo-python.py`：独立票账本／恢复／重放判读、自证与假报告反证入口。

- `evidence/lock-symlink-consistency-2026-11-21.json`：实现提交、LOCK-01–07、109 项测试、干净归档、五组旧新差分、独立锁判读与开发纠偏的综合证据。
- `evidence/lock-symlink-differential-2026-11-21.json`：lock symlink 跨 rename inode 迁移、dangling、常规／hardlink sidecar 与正常控制的原始进程结果；新端为干净归档二进制。
- `evidence/lock-symlink-preregister-2026-11-21.json`：实现前登记的七项锁判据、基线双进程突破哈希和未覆盖边界。
- `evidence/lock-symlink-clean-rebuild-2026-11-21.log`：无 `.git`、空 target 的实现提交完整重建输出。
- `../scripts/lock-symlink-differential.py`：真实双 CLI、FIFO 阻断与五组旧新锁差分入口。
- `../scripts/verify-lock-symlink-python.py`：独立 liveness／FIFO／inode／SHA-256 复核、已知答案与假报告反证入口。
- `evidence/atomic-write-consistency-2026-11-21.json`：实现提交、ATOMIC-01–07、106 项测试、干净归档、五组旧新差分、独立原子写判读与开发纠偏的综合证据。
- `evidence/atomic-write-differential-2026-11-21.json`：预置 symlink、hardlink、regular、128 冲突耗尽与正常控制的原始进程结果；新端为干净归档二进制。
- `evidence/atomic-write-preregister-2026-11-21.json`：实现前登记的七项原子写判据、基线 victim 破坏哈希和未覆盖边界。
- `evidence/atomic-write-clean-rebuild-2026-11-21.log`：无 `.git`、空 target 的实现提交完整重建输出。
- `evidence/path-consistency-2026-11-21.json`：实现提交、PATH-01–07、104 项测试、干净归档、八组旧新差分、独立路径判读与开发纠偏的综合证据。
- `evidence/path-differential-2026-11-21.json`：六类输出覆盖攻击、dot 负控制与 distinct 正常控制的原始进程结果；新端为干净归档二进制。
- `evidence/path-preregister-2026-11-21.json`：实现前登记的七项路径判据、基线破坏哈希和未覆盖边界。
- `evidence/path-clean-rebuild-2026-11-21.log`：无 `.git`、空 target 的实现提交完整重建输出。
- `evidence/egress-consistency-2026-11-17.json`：实现提交、EGR-01–07、99 项测试、无 `.git` 空 target 干净重建、48 条独立地址判据、四项假报告反证、真实旧新差分与开发纠偏的综合证据。
- `evidence/egress-differential-2026-11-17.json`：旧端 loopback 实际 verified、新默认端零命中阻断、显式本地放权代理零命中与 Registry 放权注入拒绝的原始进程证据；新端就是干净归档二进制。
- `evidence/egress-preregister-2026-11-17.json`：实现前登记的七项 egress 判据及未覆盖边界。
- `evidence/egress-clean-rebuild-2026-11-17.log`：实现提交归档的完整干净重建输出；`egress-smoke-2026-11-17.json` 与 `egress-smoke-state-2026-11-17.json` 保存对应烟测原始结果。
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
- `../scripts/verify-egress-python.py`：独立 IPv4／IPv6 分类、48 条已知答案与四类假报告反证入口。
- `../scripts/egress-differential.py`：真实 loopback target／proxy、旧新 CLI、socket hits 和独立 blocked 报告判读的差分入口。
- `../scripts/verify-path-python.py`：独立路径身份、文件系统重读、旧新差分与假报告反证入口。
- `../scripts/path-differential.py`：六类真实输出别名攻击与两个控制组的旧新进程执行入口。
- `../scripts/verify-atomic-write-python.py`：独立临时名重建、文件系统重读、四项已知答案与五类假报告反证入口。
- `../scripts/atomic-write-differential.py`：symlink／hardlink／regular／exhaustion／control 五组真实旧新进程执行入口。
- `../scripts/verify-json-budget-python.py`：独立迭代 JSON 深度／节点判读与已知答案入口。
- `../scripts/verify-wave-python.py`：独立 Python 波次重建、静态已知答案与篡改负例入口。
- `../scripts/verify-execution-python.py`：独立执行语义、状态／报告勾稽、固定夹具与 rehashed 假语义负例入口。
- `../scripts/build-all.sh`：格式、Clippy、全部测试、凭据扫描、九类 Python 判读、认知示例、波次与执行固定夹具字节对拍、执行重放和 CLI 烟测的统一重建门禁。

本轮公网正典已明确迁移到实际发布的 `.../main/...` 形式；当前字节一致只适用于本轮采集时点，不能回改 2026-11-10 的历史差异。镜像 `verified` 也不等于发布者认证。所有外部状态（推送、CI、ACK、正典 active、KEY-SYNC-01）均需要独立回执。
