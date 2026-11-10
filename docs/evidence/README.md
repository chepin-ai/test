# 证据索引

- `ci-b3b6384.json`：提交 `b3b6384` 的 GitHub Actions 外部回执及本地重建复验摘要。
- `poll-b3b6384.json`：同一提交推送后，使用仓内 `asfa-bridge-poller` 对七个公网端点的原始轮询报告。

结果：asfa-ai 自托管 outbox 为 `verified`；cisvr、ucif2、qgl、usrm、cfts 为 `http_status=404`；vinf 为 `invalid_schema`。这些结果只描述采集时点的协议可达性，不推断人员、角色或凭证状态。

## 2026-11-08

- `replay-hardening-2026-11-08.json`：43 项测试、严格静态检查、烟测、示例契约和持久化边界的本轮证据摘要。
- `poll-2026-11-08.json`：新版验证器的七端点原始报告。asfa-ai 通过 jsDelivr 只读镜像取得 `verified`；其余五项为 404，vinf 为 `invalid_schema`。仓内文件仍是正本，镜像验证不等于身份认证。
- 本轮改动尚未推送，因此没有新的外部 CI 结论。

## 2026-11-09

- `cli-persistence-2026-11-09.json`：实现提交 `d017045d2f0844ce940f1023b345a5b9522f5869` 的干净目录重建证据。46／46 测试、Clippy 零警告、凭据扫描、认知示例精确契约和烟测均通过；三项新增测试覆盖三个独立 CLI 进程的“入库→重复并消费→重启重放拒绝”、非法状态原样保留，以及后续伪造块导致整份 Outbox 零部分应用。
- `poll-2026-11-09.json`：七端点新一轮原始报告。asfa-ai 经 jsDelivr 只读镜像取得 `verified`；cisvr、ucif2、qgl、usrm、cfts 为 404；vinf 为 `invalid_schema`。
- 推送第一次遇到连接失败，重试后停在非交互认证缺失；远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，本轮没有新外部 CI。正典注册表复核仍为 `asfa-ai=conditional`。

## 2026-11-10

- `attack-consistency-2026-11-10.json`：实现提交 `9347c470cd0a57a9fe5baf0b907bf7c308e08e25` 的干净归档重建证据。56／56 测试与全部门禁通过；四组旧新 CLI 差分覆盖重复 JSON 成员、跨网络状态复用、降高和同高分叉；另含 Python 独立判读、自证负例、JCS 候选自身 14 项测试及未集成边界。
- `poll-2026-11-10.json`：使用上述干净归档产物采集的七端点原始报告。asfa-ai 为 `verified`，其余五项为 404，vinf 为 `invalid_schema`。
- 公网镜像与本地正本的字节和完整语义均不相等，字段级唯一差异为 `$.url`，`hash_chain` 相同且双方均通过 Python 判读。不得将该结果写成 `remote=local`；显式 `canonical_url` 与镜像策略仍未实现。
- 本地 checkpoint 不抵御整份状态快照回滚；单写者、无独立 witness／quorum、无完整 JCS V2 等边界已随证据登记。证据生成时没有新的外部 CI、cisvr ACK、正典升 active 或 KEY-SYNC-01 完成回执；最终推送结果须另经远端对拍确认。
