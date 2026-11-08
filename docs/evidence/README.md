# 证据索引

- `ci-b3b6384.json`：提交 `b3b6384` 的 GitHub Actions 外部回执及本地重建复验摘要。
- `poll-b3b6384.json`：同一提交推送后，使用仓内 `asfa-bridge-poller` 对七个公网端点的原始轮询报告。

结果：asfa-ai 自托管 outbox 为 `verified`；cisvr、ucif2、qgl、usrm、cfts 为 `http_status=404`；vinf 为 `invalid_schema`。这些结果只描述采集时点的协议可达性，不推断人员、角色或凭证状态。

## 2026-11-08

- `replay-hardening-2026-11-08.json`：43 项测试、严格静态检查、烟测、示例契约和持久化边界的本轮证据摘要。
- `poll-2026-11-08.json`：新版验证器的七端点原始报告。asfa-ai 通过 jsDelivr 只读镜像取得 `verified`；其余五项为 404，vinf 为 `invalid_schema`。仓内文件仍是正本，镜像验证不等于身份认证。
- 本轮改动尚未推送，因此没有新的外部 CI 结论。
