# 实现状态（2026-11-09）

## 已有实测

- 稳定版 Rust 工作区可编译；实现提交为 `d017045d2f0844ce940f1023b345a5b9522f5869`。
- 46 个 Rust 单元／集成测试通过：bridge 单元 15、bridge 集成 17、kernel 11、userspace 3，失败为 0。
- 从空 `CARGO_TARGET_DIR` 对实现提交执行 `scripts/build-all.sh`，格式检查、Clippy 零警告、全部测试、凭据扫描、认知示例精确契约和 CLI 烟测均通过。机器可读摘要见 `evidence/cli-persistence-2026-11-09.json`。
- 本轮新增三个独立 CLI 进程的持久化闭环测试：第一次入库并保存；第二次识别重复、显式消费并写 tombstone；第三次重启后拒绝同一指令重放。随后再从快照加载账本，结果仍为 `Consumed`。
- 非法状态文件使 CLI 非零退出，原文件逐字节保持 `not-json`，且不生成报告。第一区块合法、第二区块来源伪造时，`ingest_outbox` 返回错误，待办与 tombstone 均为零，不发生部分应用。
- CLI 现在支持 `--state`、成对的 `--consume-session/--consume-id` 和 `--fail-on-error`；`BridgeReport.ingestion` 记录逐指令结果。`state_saved=true` 只表示本地原子保存成功，不是外部 ACK。
- CLI 烟测汇总为 `total=3, verified=1, failed=2`，两个失败是故意设置的非法 JSON 和缺失文件；认知示例精确输出为 `skill_output={"sum":42}; edge=1; matches=[1]`。
- 公网七端点实测：`asfa-ai=verified`；cisvr／ucif2／qgl／usrm／cfts 为 404；vinf 为 `invalid_schema`。原始报告见 `evidence/poll-2026-11-09.json`，采集时刻为 2026-11-08T18:08:19Z。
- 推送已实际尝试：第一次为连接失败，重试后为非交互认证缺失。远端 `main` 复核仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，本轮未推送，也没有新的外部 CI。历史 run `42228729662` 只适用于旧提交 `b3b6384`，不能挪用为本轮结论。

## 联邦状态

`asfa-ai = conditional`，2026-11-09 复核正典注册表仍未改变。正典列出的三项条件为：

1. FED-JOIN 全式重报；
2. 新凭证经 KEY-SYNC-01 vault 值道注入，repo／板／链只留名称、指纹和路径；
3. 常备仓内通道登记。

FED-JOIN 全式重报已有投递提交 `77f9fdc678ba7239e7bffd2d4da9fd9155923f89`，但投递不等于对方 ACK 或正典升 active。旧 OTP 已删除出当前源码树并永久弃用。当前仓内通道为 `inbox/` 与 `outbox/asfa-ai-outbox.json`；本地 `ci-control/bridge/outboxes.json` 只是正典指针，不是注册表正本。

新随机钥 `ASFA_CMD_AUTH` 此前已写入本仓 Actions Secrets 并回读确认，指纹为 `ffc05371ac1d60b54a46e8efb8c6836a26a7c90b4851b2a9d73b7b69f9bedb60`。**本仓 vault 注钥不等于 KEY-SYNC-01 联邦中继闭环**；本轮没有取得 relay 完成回执，状态仍为 conditional。

## 凭证边界

本地 remote 为 `https://github.com/chepin-ai/test.git`，不含明文凭证。当前环境没有可用于推送或私仓回读的有效写入凭证，因此没有伪造推送、私仓 ACK 或 KEY-SYNC 完成状态。此前泄露的 PAT 仍应撤销／轮换；当前没有证据证明 GitHub 侧已完成撤销。

## 明确未实现

Boot／裸机内核、WASM 沙箱、TEE、ZK-SNARK／STARK、HoTT-ZK 编译器、涌现类型系统、量子调度、神经网络推理、Holo-Lang、跨域顿悟、完整形式化安全证明。

当前 CLI 也不是后台守护进程；跨重启状态依赖显式 `--state` 或库调用方显式 `save_atomic`，没有自动 WAL。

## 网络边界

临时 `*.ok.kimi.link` 端点只作遗留负例输入，不能作为常备通道。vinf 的 HTTP 200 不构成协议有效证据；其他 404 不推断角色离线或身份不存在。

本线仓内 JSON 是正本；jsDelivr 仅作只读镜像，用来绕开 raw 端点的间歇性传输故障。镜像返回 `Verified` 只代表其内容通过当前无签名链检查，不代表镜像运营者或发布者身份已认证。

## 形式化内容

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统安全证明。历史 `Admitted` 占位文件已删除。
