# ASFA-OS-Xi：可验证认知原语与 Outbox 桥接器

当前仓库是一个**可编译、可测试的 Rust 工作区**，不是已经完成 Boot 的操作系统，也不包含 ZK 证明器、HoTT 编译器或量子运行时。

## 已实现

- `asfa-kernel`
  - n 元超边：唯一 ID、并发创建、子集检索、共享 Agent 遍历；
  - 认知记忆：真实键值存取、有限向量校验、最近位置导航；
  - Operad：元数检查、顺序组合、错误传播。
- `asfa-userspace`
  - Agent 身份与位置；
  - 可执行 JSON Skill 注册表。
- `asfa-bridge-poller`
  - 默认 HTTPS 轮询；`file://` 与 HTTP 必须显式授权，自动重定向关闭且 3xx 显式失败；
  - HTTP(S) 默认 public-only egress：IP 字面量直接分类，域名只解析一次并检查组内全部地址；实际连接固定到已验证地址，保留原 Host／TLS server name，环境代理关闭；
  - loopback、私网、link-local、shared、文档、保留、组播及 IPv4-mapped／NAT64／transition 等目的地址在拨号前以 `blocked_egress` 失败；只有进程级 `--allow-non-public-egress` 可为本地测试／受控遗留部署放权，Registry 无法开启；
  - `Outbox.url` 绑定显式正典 URL，只读镜像可在声明后与读取 URL 不同；
  - 无签名哈希链逐块重算；
  - Outbox、Registry、Snapshot 统一严格 JSON 入口，递归拒绝重复、转义后同名键及未知协议字段；
  - 404、非 JSON、schema 错误、身份错配、坏链、超限文档均产生显式负结果；
  - 指令只在区块负载内计入已验证集合，并强制 `from == session`；
  - 结构化会话键去重、同 ID 内容冲突拒绝、过期复核、消费 tombstone 防重放；
  - v4 账本绑定 `network_name` 与完整安全策略 `policy_hash`，跨网络或同网络策略混配直接失败且不覆盖原状态；
  - 每会话持久化 `(height,latest)` 检查点，拒绝降高、同高分叉及长链改写旧前缀；
  - 确定性账本快照、原子保存、恢复矛盾检查，重载后仍拒绝已消费指令与历史分叉；
  - 账本临时项以 `create_new` 独占分配；预置 symlink／hardlink／普通文件不会被跟随、截断或改名，最多尝试 128 个候选后显式失败；
  - CLI 可直接执行“轮询→完整链复验→入库→显式消费→原子保存”，并输出逐指令 ingestion 事件；
  - 任一后续区块伪造时整份 Outbox 不入库，不用前面的合法块制造部分应用；
  - 注册表／会话／文档 trust 交叉核对，HMAC 和完整签名明确返回“未支持”；
  - Outbox 与 Registry 均按 2 MiB 上限读取，Snapshot 上限 16 MiB；同时检查 metadata 和实际读回字节；
  - 三类 JSON 入口共用 64 层深度与 16384 个值节点的全文档预算，开放 `mailbox`／`payload` 也不能绕过；
  - CLI 默认 60 秒全轮询墙钟预算，`--poll-timeout-ms` 只能调低；会话间检查 deadline，活动 HTTP 请求只获得剩余时间；
  - Registry 最多 64 个会话；pending、消费 tombstone、单 Outbox 指令数与 Snapshot 写字节均有硬上限，容量失败整批回滚；
  - `--state` 使用解析后目标对应的稳定 sidecar OS 排他锁，最终状态路径符号链接别名也会竞争同一把锁；预置 lock symlink（含 dangling）在轮询、消费、状态变化和报告前显式拒绝，Unix 实际 open 使用 `O_NOFOLLOW`；常规／hardlink sidecar 跨状态 rename 仍锁定原 inode；
  - `--state`、`--out`、`--wave-out`、`--execution-out`、`--ticket-out` 在锁、轮询、执行和写入前做路径身份预检；解析后同路径、符号链接／`..` 别名及既有硬链接均失败关闭；
  - QF-OS `qfos-wave-plan/v1`：从已验证账本生成确定性、按来源轮转、全局／来源双配额的计划，绑定 network、policy、snapshot 与 plan 摘要；计划生成本身只读；
  - 仓内 `qfos-exec-v1`：显式执行计划中的 `engine.sum`／`engine.sha256`，无 shell、网络或外部进程；真实输出、成功回执、五类死信与 consumed tombstone 在同一快照提交，重启只恢复、不重复执行；
  - 一次性任务票：Mint 创建根控制票与逐作业工作票，Transfer 指定新接收人，Revoke 整根失效，Execute 将票消费、回执／死信、tombstone 与审计交易放入同一 v5 暂存快照；
  - 工作票按 `(session,id)` 唯一链和最高序列号取链尖，绑定 `plan_hash`；每根默认 20 票，第 21 票失败且不消费父票；多作业整波要求全部链尖属于同一 agent，无拆波执行接口；
  - v5 恢复重建血缘、spent 集合与 Execute↔结果绑定，拒绝双花、跨作业父链、多基票、序列断裂、结果缺失，以及根 Revoke 同一时间或之后的 Transfer／Execute；无票状态继续序列化为 v4，固定字节不漂移；
  - CLI 在任何运行时副作用前拒绝 `--execute-wave` 与 Mint／Transfer／Revoke 同用，防止旧执行结果与票变更组成没有 Execute 交易的混合历史；单独旧执行及单独票变更保持兼容。
- `lean/Qf`＋`federation/`
  - 钉定 Lean `v4.35.0` 的 core-only 最小约束核，实际证明非传递关系拒绝、lossy 投影不降格、非 FORMAL 拒绝、同键异命题冲突和同命题来源保持；
  - 真实构建生成 declaration capsule、环境 attestation、registry 和六类投影；独立 Python 重建声明／证据／同步语义并亲自拒绝伪造报告；
  - 只声称本线 `FORMAL_R1`，不把普通构建升级为沙箱多内核、跨机、跨线或全局激活。
- QI-OS 大周天适配
  - 复用 QI-OS 原生工单、append-only 账本和独立 crosscheck，不另造共识格式；Lean 野问与 usrm peer 可经真实 issue 通道发送和轮询；
  - 独立判读器重建 canonical 工单与哈希链，严格区分 `DELIVERED`、有效答件、crosscheck 和 promotion；非合规 bot 回复不得冒充 ACK。

## 复验

需要稳定版 Rust、rustfmt 和 clippy：

```bash
cargo test --workspace --all-targets --locked
cargo run --example cognitive_demo -p asfa-userspace
python3 scripts/verify-outbox-python.py --self-test \
  fixtures/python-oracle-outbox.json outbox/asfa-ai-outbox.json
python3 scripts/verify-policy-python.py --fixture fixtures/policy-oracle.json
python3 scripts/verify-egress-python.py --self-test
python3 scripts/verify-json-budget-python.py
python3 scripts/verify-path-python.py --self-test
python3 scripts/verify-atomic-write-python.py --self-test
python3 scripts/verify-lock-symlink-python.py --self-test
python3 scripts/verify-wave-python.py \
  --expect-plan-hash 5b27a80652ea74fc1b11e07033119ea49708018244325e5dae56f0f6bb88ca34
python3 scripts/verify-execution-python.py --closed-world --self-test \
  --expect-plan-hash f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a \
  --expect-execution-hash 4cefca364f55ef97a41aeb580ab01b6c16c7a754a02acc78b23e14fc6da5a78c
python3 scripts/verify-ticket-utxo-python.py --self-test
python3 scripts/verify-ticket-utxo-python.py \
  --report docs/evidence/ticket-utxo-differential-2026-11-21.json \
  --out /tmp/asfa-ticket-consistency-recheck.json
cmp /tmp/asfa-ticket-consistency-recheck.json \
  docs/evidence/ticket-utxo-consistency-2026-11-21.json
python3 scripts/verify-ticket-mixed-mode-python.py --self-test
python3 scripts/verify-ticket-mixed-mode-python.py \
  --report docs/evidence/ticket-mixed-mode-differential-2026-11-23.json \
  --out /tmp/asfa-ticket-mixed-consistency-recheck.json
cmp /tmp/asfa-ticket-mixed-consistency-recheck.json \
  docs/evidence/ticket-mixed-mode-consistency-2026-11-23.json
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.smoke.json \
  --out /tmp/asfa-smoke-report.json \
  --state /tmp/asfa-smoke-state.json \
  --now 1000
python3 scripts/verify-policy-python.py \
  --registry config/sessions.smoke.json \
  --snapshot /tmp/asfa-smoke-state.json

# 带持久化账本运行；状态不存在时新建，非法状态直接失败且不覆盖
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.json \
  --state /tmp/asfa-directive-ledger.json \
  --out /tmp/asfa-live-report.json

# 显式消费一个已入库指令；两个 consume 参数必须成对出现
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.json \
  --state /tmp/asfa-directive-ledger.json \
  --consume-session asfa-ai \
  --consume-id DIRECTIVE_ID \
  --out /tmp/asfa-consume-report.json

# 生成 QF-OS 波次计划；不改变账本、不执行 action
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.wave.json \
  --state /tmp/asfa-wave-state.json \
  --wave-out /tmp/asfa-wave-plan.json \
  --now 100 --wave-max-jobs 3 --wave-max-per-source 2

# 先在 50 时刻保存执行恢复锚点，再在 100 时刻执行同一计划
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-exec-state.json \
  --wave-out /tmp/asfa-exec-plan.json --now 50
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.execution.json \
  --state /tmp/asfa-exec-state.json \
  --wave-out /tmp/asfa-exec-plan.json \
  --execute-wave --execution-out /tmp/asfa-exec-report.json --now 100

# 任务票：铸票后可 Transfer 或 Revoke；下列写操作是替代分支，不应在同一状态依次全跑
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.execution.json --state /tmp/asfa-ticket-state.json \
  --out /tmp/asfa-ticket-mint-bridge.json --wave-out /tmp/asfa-ticket-plan.json \
  --ticket-mint-root nonce-1 --ticket-controller root --ticket-agent alice \
  --ticket-out /tmp/asfa-ticket-mint.json --now 50
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.execution.json --state /tmp/asfa-ticket-state.json \
  --out /tmp/asfa-ticket-transfer-bridge.json \
  --ticket-transfer TICKET_ID --ticket-to bob \
  --ticket-out /tmp/asfa-ticket-transfer.json --now 75
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.execution.json --state /tmp/asfa-ticket-state.json \
  --out /tmp/asfa-ticket-revoke-bridge.json \
  --ticket-revoke-root ROOT_TICKET_ID \
  --ticket-out /tmp/asfa-ticket-revoke.json --now 80
# 在未撤销且 alice 持有全部当前链尖的状态上执行；Revoke 后此操作必须失败
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.execution.json --state /tmp/asfa-ticket-state.json \
  --out /tmp/asfa-ticket-execute-bridge.json --wave-out /tmp/asfa-ticket-plan.json \
  --execute-wave --ticketed-execution --ticket-agent alice \
  --execution-out /tmp/asfa-ticket-execution.json \
  --ticket-out /tmp/asfa-ticket-execute.json --now 100
```

任何 Mint／Transfer／Revoke 都不得与 `--execute-wave` 同用；应先单独完成票变更，再单独执行任务票执行。非法组合在 Registry 读取、状态锁、轮询和输出前失败，不改变原状态。

`--fail-on-error` 会把轮询失败、入库冲突／非法指令、消费目标不存在以及新产生或恢复的执行死信变成非零退出；重复、已消费重放拦截和过期指令仍保留在报告中。只有传入 `--state` 才保存账本，库 API 调用同样需要显式 `save_atomic`，当前没有自动 WAL。v4／v5 状态同时绑定 `network_name` 与 Registry 安全策略摘要 `policy_hash`；旧 v1／v2／v3、跨网络及同网络策略变化均不做隐式迁移，说明性 `role`／`note` 变化不影响兼容性。执行模式先保存原计划，再暂存执行并原子保存 v4／v5 状态，最后写执行报告；报告写坏后可从计划与持久回执恢复。CLI 容量参数只能把硬上限调低，不能调高；所有声明输出先解析实际目标并判重，sidecar 锁也使用解析后的状态目标；lock sidecar 自身不得是符号链接，Unix 实际 open 使用 `O_NOFOLLOW`。账本保存只使用本进程以 `create_new` 成功创建的临时项，冲突有界重试；但创建成功后至 rename 前的恶意路径替换仍未关闭。上述预检不能消除验证后遭恶意改名的 TOCTOU 或取锁后的 lock pathname 替换，也不提供跨进程硬链接通用锁、分布式锁或非协作写者隔离；非 Unix check/open 竞态不作已关闭声称。检查点只提供本地历史一致性；整份快照被旧文件替换、独立 witness、底层 DNS 强制取消／线程回收与进程级内存／CPU／文件描述符隔离仍不在保障范围内。

一键全部门禁（`/mnt` 等禁止执行位挂载下也能构建）：

```bash
bash scripts/build-all.sh
# 另需与 lean/lean-toolchain 一致的 lake；提交级 Lean R1 门禁：
bash scripts/lean-federation-gate.sh FULL_IMPLEMENTATION_COMMIT /tmp/asfa-lean-gate "$PWD"
python3 scripts/verify-lean-federation-python.py --self-test
```

预期：119 项 Rust 测试通过（bridge 单元 56、bridge 集成 49、kernel 11、userspace 3，其中 ticket 模块 9 项）；烟测汇总为 `total=3, verified=1, failed=2`，两个失败分别是故意设置的非法 JSON 和缺失文件。egress 预注册 48 个 IPv4／IPv6 已知答案由 Rust 与独立 Python 同时复核；旧新真实进程差分证明旧端访问 loopback 并 verified，新默认端在零 TCP accept 下返回 `blocked_egress`，显式本地放权仍可达目标且六类恶意代理环境变量零命中。输出路径八组旧新差分覆盖轮询、wave、execution、父路径、dangling symlink、符号链接父目录和硬链接：六个攻击用例旧端退出 0 并发生覆盖，干净新端均在锁和写入前退出 2；独立 Python 以 realpath／samefile／stat 复判并拒绝五类假报告。原子写五组差分覆盖预置 symlink、hardlink、普通文件、128 项冲突耗尽与正常控制：旧端在前三类攻击中均 exit 0 并覆盖或改名既有项；干净新端对可绕过冲突安全重试，对耗尽显式 exit 2，且全部 sentinel 保留。独立 Python 重读文件类型、链接目标、文件身份与 SHA-256，并以四项文件系统已知答案和五类假报告先行自证。状态锁五组差分进一步覆盖预置 lock symlink 的跨 rename inode 迁移、dangling symlink、常规锁、hardlink 锁和正常控制：旧端首进程存活时第二进程可消费，干净新端在轮询、状态变化和 FIFO 输出前失败；独立 Python 以五项已知答案和六类假报告自证后复判。QF-OS 静态向量准入 `a1 → b1 → a2`，两个延后项分别由来源配额和全局配额解释。执行夹具包含 7 项作业，实测 2 个真实成功回执与 5 个显式死信，重放为 7 项 skipped 且账本字节不变；Python 独立重建输出与失败类别，并以 5 个篡改样本自证，其中包含篡改后重算哈希的假输出与假失败类别。独立 JSON 判读以迭代遍历复核深度、全文档节点数、转义重复键及五个已知答案负例。任务票最终差分为 9 组、48 个真实进程步骤；独立 Python 先通过 3 个已知答案、1 个合成有效、4 个合成拒绝并拒绝伪造真实报告，再验收最终 PASS。合法重放不新增票交易且 v5 状态字节不变；撤销后伪造历史由 Rust 与 Python 同时拒绝。最终差分新端来自无 `.git`、初始无 target 的实现提交归档，旧端来自同基线提交重建，哈希与环境重置注记均入证据索引。混合模式修复另以 5 组、17 个真实进程步骤复现旧端 Transfer／Revoke 混合历史，并证明新端在副作用前拒绝且零输出；独立判读 PASS，Transfer 原时间戳吸收反例与 Revoke 不可经任务票接口恢复的边界均保留。

## 证据与协议

- [实现状态与未覆盖边界](docs/STATUS.md)
- [实际架构](docs/ARCHITECTURE.md)
- [全局 Lean 证据联邦与数学操作系统方案](docs/LEAN_FEDERATION.md)
- [Lean 联邦 R1 证据总索引](docs/evidence/lean-federation-evidence-manifest-2026-11-23.json)
- [QI-OS 原生大周天与独立读回](docs/QI_OS_WAVE.md)
- [QI-OS 大周天证据总索引](docs/evidence/qios-wave-evidence-manifest-2026-11-23.json)
- [ASFA／QFA 身份、仓谱与协同地址](docs/ASFA_QFA_IDENTITY.md)
- [Outbox / 哈希链协议](docs/BRIDGE_PROTOCOL.md)
- [任务票最终证据总索引](docs/evidence/ticket-utxo-evidence-manifest-2026-11-21.json)
- [混合执行／票变更门禁证据总索引](docs/evidence/ticket-mixed-mode-evidence-manifest-2026-11-23.json)
- [形式化结构、规范同构与攻击矩阵](docs/ISOMORPHISM_ATTACK_MATRIX.md)
- [仓内 inbox](inbox/README.md)
- [本地注册表指针](ci-control/bridge/outboxes.json)

## 诚实边界

“无签名哈希链”只证明数据内部一致性，不证明发布者身份。`qfos-exec-v1` 是本仓定义的纯内置执行契约，不是已验证的外部 QF-OS 正典或 QIOS 适配器；回执与报告 SHA-256 不是签名，本地恢复幂等也不是分布式 exactly-once。当前 Coq 文件只是一个高度定理示例；Lean 联邦切片也只覆盖六个关系／同步定理，二者都不能据此宣称系统经过形式化安全验证。详细限制见状态文档。
