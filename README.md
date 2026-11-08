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
  - `file://`、HTTP(S) 轮询；
  - 无签名哈希链逐块重算；
  - 404、非 JSON、schema 错误、身份错配、坏链、超限文档均产生显式负结果；
  - 指令只在区块负载内计入已验证集合，并强制 `from == session`；
  - 结构化会话键去重、同 ID 内容冲突拒绝、过期复核、消费 tombstone 防重放；
  - 确定性账本快照、原子保存、恢复矛盾检查，重载后仍拒绝已消费指令；
  - CLI 可直接执行“轮询→完整链复验→入库→显式消费→原子保存”，并输出逐指令 ingestion 事件；
  - 任一后续区块伪造时整份 Outbox 不入库，不用前面的合法块制造部分应用；
  - 注册表／会话／文档 trust 交叉核对，HMAC 和完整签名明确返回“未支持”；
  - 文件与 HTTP 均按 2 MiB 上限流式读取，避免先整文件载入再判超限。

## 复验

需要稳定版 Rust、rustfmt 和 clippy：

```bash
cargo test --workspace --all-targets --locked
cargo run --example cognitive_demo -p asfa-userspace
cargo run -p asfa-bridge-poller -- \
  --config config/sessions.smoke.json \
  --out /tmp/asfa-smoke-report.json \
  --now 1000

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
```

`--fail-on-error` 会把轮询失败、入库冲突／非法指令和消费目标不存在变成非零退出；重复、已消费重放拦截和过期指令仍保留在报告中。只有传入 `--state` 才保存账本，库 API 调用同样需要显式 `save_atomic`，当前没有自动 WAL。

一键全部门禁（`/mnt` 等禁止执行位挂载下也能构建）：

```bash
bash scripts/build-all.sh
```

预期：全部 Rust 测试通过；烟测汇总为 `total=3, verified=1, failed=2`，两个失败分别是故意设置的非法 JSON 和缺失文件。

## 证据与协议

- [实现状态与未覆盖边界](docs/STATUS.md)
- [实际架构](docs/ARCHITECTURE.md)
- [Outbox / 哈希链协议](docs/BRIDGE_PROTOCOL.md)
- [仓内 inbox](inbox/README.md)
- [本地注册表指针](ci-control/bridge/outboxes.json)

## 诚实边界

“无签名哈希链”只证明数据内部一致性，不证明发布者身份。当前 Coq 文件只是一个高度定理示例，不能据此宣称系统经过形式化安全验证。详细限制见状态文档。
