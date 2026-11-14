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
  - `Outbox.url` 绑定显式正典 URL，只读镜像可在声明后与读取 URL 不同；
  - 无签名哈希链逐块重算；
  - Outbox、Registry、Snapshot 统一严格 JSON 入口，递归拒绝重复、转义后同名键及未知协议字段；
  - 404、非 JSON、schema 错误、身份错配、坏链、超限文档均产生显式负结果；
  - 指令只在区块负载内计入已验证集合，并强制 `from == session`；
  - 结构化会话键去重、同 ID 内容冲突拒绝、过期复核、消费 tombstone 防重放；
  - v3 账本绑定 `network_name` 与完整安全策略 `policy_hash`，跨网络或同网络策略混配直接失败且不覆盖原状态；
  - 每会话持久化 `(height,latest)` 检查点，拒绝降高、同高分叉及长链改写旧前缀；
  - 确定性账本快照、原子保存、恢复矛盾检查，重载后仍拒绝已消费指令与历史分叉；
  - CLI 可直接执行“轮询→完整链复验→入库→显式消费→原子保存”，并输出逐指令 ingestion 事件；
  - 任一后续区块伪造时整份 Outbox 不入库，不用前面的合法块制造部分应用；
  - 注册表／会话／文档 trust 交叉核对，HMAC 和完整签名明确返回“未支持”；
  - Outbox 与 Registry 均按 2 MiB 上限读取，Snapshot 上限 16 MiB；同时检查 metadata 和实际读回字节；
  - Registry 最多 64 个会话；pending、消费 tombstone、单 Outbox 指令数与 Snapshot 写字节均有硬上限，容量失败整批回滚；
  - `--state` 使用稳定 sidecar 的 OS 排他锁，协作写者竞争时失败关闭，不再以原子 rename 冒充多写者互斥；
  - QF-OS `qfos-wave-plan/v1`：从已验证账本生成确定性、按来源轮转、全局／来源双配额的计划，绑定 network、policy、snapshot 与 plan 摘要；只规划，不执行引擎。

## 复验

需要稳定版 Rust、rustfmt 和 clippy：

```bash
cargo test --workspace --all-targets --locked
cargo run --example cognitive_demo -p asfa-userspace
python3 scripts/verify-outbox-python.py --self-test \
  fixtures/python-oracle-outbox.json outbox/asfa-ai-outbox.json
python3 scripts/verify-policy-python.py --fixture fixtures/policy-oracle.json
python3 scripts/verify-wave-python.py \
  --expect-plan-hash fefb2704c277115cf4f88e2215cfb7a10cb508694a43527c300700ed47003302
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
```

`--fail-on-error` 会把轮询失败、入库冲突／非法指令和消费目标不存在变成非零退出；重复、已消费重放拦截和过期指令仍保留在报告中。只有传入 `--state` 才保存账本，库 API 调用同样需要显式 `save_atomic`，当前没有自动 WAL。v3 状态同时绑定 `network_name` 与 Registry 安全策略摘要 `policy_hash`；旧 v1／v2、跨网络及同网络策略变化均不做隐式迁移，说明性 `role`／`note` 变化不影响兼容性。CLI 容量参数只能把硬上限调低，不能调高；sidecar 锁只约束使用相同词法状态路径的协作进程，不是分布式锁。检查点只提供本地历史一致性；整份快照被旧文件替换、独立 witness、非协作写者与全轮询总 deadline 仍不在保障范围内。

一键全部门禁（`/mnt` 等禁止执行位挂载下也能构建）：

```bash
bash scripts/build-all.sh
```

预期：78 项 Rust 测试通过；烟测汇总为 `total=3, verified=1, failed=2`，两个失败分别是故意设置的非法 JSON 和缺失文件。QF-OS 静态向量准入 `a1 → b1 → a2`，两个延后项分别由来源配额和全局配额解释，Python 独立重建与字节对拍通过。

## 证据与协议

- [实现状态与未覆盖边界](docs/STATUS.md)
- [实际架构](docs/ARCHITECTURE.md)
- [Outbox / 哈希链协议](docs/BRIDGE_PROTOCOL.md)
- [形式化结构、规范同构与攻击矩阵](docs/ISOMORPHISM_ATTACK_MATRIX.md)
- [仓内 inbox](inbox/README.md)
- [本地注册表指针](ci-control/bridge/outboxes.json)

## 诚实边界

“无签名哈希链”只证明数据内部一致性，不证明发布者身份。当前 Coq 文件只是一个高度定理示例，不能据此宣称系统经过形式化安全验证。详细限制见状态文档。
