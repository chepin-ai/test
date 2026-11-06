# 实现状态（2026-11-06）

## 已有实测

- 稳定版 Rust 工作区可编译。
- 31 个 Rust 单元／集成测试覆盖：并发 ID、子集检索、向量导航、Operad 组合、Skill 执行、哈希链篡改、HTTP 200／404、非 JSON、schema 与身份错配、HMAC 未支持、超大文档、区块内指令与顶层未认证指令分离。
- CLI 烟测配置含一个正例和两个故意负例；最终通过证据以 CI／本地复跑输出为准。

## 联邦状态

`asfa-ai = conditional`。升 active 仍须同时满足：

1. FED-JOIN 全式重报；
2. 新凭证经 KEY-SYNC-01 vault 值道注入，repo／板／链只留名称、指纹和路径；
3. 常备仓内通道登记。

旧 OTP 已删除出当前源码树，且按裁决永不再用。当前仓内通道为 `inbox/` 与 `outbox/asfa-ai-outbox.json`。本地 `ci-control/bridge/outboxes.json` 只是正典指针，不是联邦注册表正本。

## 明确未实现

Boot／裸机内核、WASM 沙箱、TEE、ZK-SNARK／STARK、HoTT-ZK 编译器、涌现类型系统、量子调度、神经网络推理、Holo-Lang、跨域顿悟、完整形式化安全证明。

## 网络边界

临时 `*.ok.kimi.link` 端点只作遗留负例输入，不能作为常备通道。vinf 的 HTTP 200 不构成协议有效证据；其他 404 不推断角色离线或身份不存在。

## 形式化内容

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统安全证明。历史 `Admitted` 占位文件已删除。
