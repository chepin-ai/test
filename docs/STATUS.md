# 实现状态（2026-11-06）

## 已有实测

- 稳定版 Rust 工作区可编译。
- 31 个 Rust 单元／集成测试覆盖：并发 ID、子集检索、向量导航、Operad 组合、Skill 执行、哈希链篡改、HTTP 200／404、非 JSON、schema 与身份错配、HMAC 未支持、超大文档、区块内指令与顶层未认证指令分离。
- CLI 烟测配置含一个正例和两个故意负例；最终通过证据以 CI／本地复跑输出为准。
- 删除构建缓存后的重建级复验通过；外部 GitHub Actions run `42228729662` 已返回 `completed/success`，原始摘要见 `evidence/ci-b3b6384.json`。
- 公网七端点实测：`asfa-ai=verified`；cisvr／ucif2／qgl／usrm／cfts 为 404；vinf 为 schema 不符。原始报告见 `evidence/poll-b3b6384.json`。

## 联邦状态

`asfa-ai = conditional`。升 active 仍须同时满足：

1. FED-JOIN 全式重报；
2. 新凭证经 KEY-SYNC-01 vault 值道注入，repo／板／链只留名称、指纹和路径；
3. 常备仓内通道登记。

旧 OTP 已删除出当前源码树，且按裁决永不再用。当前仓内通道为 `inbox/` 与 `outbox/asfa-ai-outbox.json`。本地 `ci-control/bridge/outboxes.json` 只是正典指针，不是联邦注册表正本。

新随机钥 `ASFA_CMD_AUTH` 已通过 SealedBox 写入本仓 Actions Secrets 并回读确认，指纹为 `ffc05371ac1d60b54a46e8efb8c6836a26a7c90b4851b2a9d73b7b69f9bedb60`。**这只是本仓 vault 注钥，不等同于 KEY-SYNC-01 联邦中继闭环**；当前未找到活跃 relay，故状态仍保持 conditional。

## 明确未实现

Boot／裸机内核、WASM 沙箱、TEE、ZK-SNARK／STARK、HoTT-ZK 编译器、涌现类型系统、量子调度、神经网络推理、Holo-Lang、跨域顿悟、完整形式化安全证明。

## 网络边界

临时 `*.ok.kimi.link` 端点只作遗留负例输入，不能作为常备通道。vinf 的 HTTP 200 不构成协议有效证据；其他 404 不推断角色离线或身份不存在。

## 形式化内容

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统安全证明。历史 `Admitted` 占位文件已删除。
