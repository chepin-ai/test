# 实现状态（本轮实测证据：2026-11-10）

## 已有实测

- 稳定版 Rust 工作区可编译；实现提交为 `9347c470cd0a57a9fe5baf0b907bf7c308e08e25`。
- 56 个 Rust 单元／集成测试通过：bridge 单元 20、bridge 集成 22、kernel 11、userspace 3，失败为 0。
- 从该实现的 Git 归档解到干净目录，并使用空 `CARGO_TARGET_DIR` 完整执行 `scripts/build-all.sh`。格式检查、Clippy 零警告、56 项测试、凭据扫描、Python 独立判读及负例自证、认知示例精确契约和 CLI 烟测均通过。归档 SHA-256 为 `e4a234d2585b995b8f0645588b0ccb9acf5d625a3a97f8ee27346ffa69406d85`。
- 认知示例精确输出仍为 `skill_output={"sum":42}; edge=1; matches=[1]`。CLI 烟测为 `total=3, verified=1, failed=2`，两个失败是故意设置的非法 JSON 和缺失文件。
- 综合机器可读证据见 `evidence/attack-consistency-2026-11-10.json`；攻击、规范映射与未覆盖边界见 `ISOMORPHISM_ATTACK_MATRIX.md`。

## 本轮新增安全性质

1. **严格 JSON 成员唯一性**：Outbox、Registry 和 LedgerSnapshot 在 schema 转换前递归拒绝重复成员；`a` 与 `\u0061` 在转义解码后判重。该门禁不是完整 RFC 8785 JCS。
2. **网络空间绑定**：账本快照升级为 `asfa-directive-ledger/v2`，保存并复核 `network_name`。旧 v1、无网络身份或跨网络状态不隐式迁移；拒绝时原状态字节不变且不生成新报告。
3. **本地历史一致性**：每个 session 保存 `(height,latest)` 检查点。降高返回 `Rollback`；同高不同链头、或更长链改写旧高度前缀均返回 `Fork`；合法重读和保留旧前缀的延长放行。检查点与指令、tombstone 一同进入原子快照，重启后仍生效。
4. **零部分应用**：完整验链、指令来源复验和检查点对拍均先于指令入库；后续伪造块或检查点异常不会留下该 Outbox 的部分指令、tombstone 或检查点。

这些性质只覆盖本机已有视图。检查点是 O(n) 全链前缀对拍，不是 Merkle consistency proof；整份状态文件被旧快照替换仍需外部单调锚、签名 checkpoint 或独立 witness／quorum。

## 旧新 CLI 差分

旧实现为 `d017045d2f0844ce940f1023b345a5b9522f5869`，新实现为 `9347c470cd0a57a9fe5baf0b907bf7c308e08e25`。四组真实进程级 A/B 均通过预注册差分判据：

| 输入 | 旧端实测 | 新端实测 |
|---|---|---|
| 重复 JSON 成员 | 返回 0，`verified` | 返回 2，`invalid_json` |
| 网络 B 复用网络 A 状态 | 返回 0，把 A 的指令报为 `duplicate=1`，v1 无网络身份 | 返回 2，状态不变，不生成报告 |
| 链高 2→1 | 返回 0，`duplicate=1` | 返回 2，错误含 `Rollback`，状态不变，不生成报告 |
| 同高不同链头 | 返回 0，`conflict=1` | 返回 2，错误含 `Fork`，状态不变，不生成报告 |

跨网络用例的首轮判据曾错误要求旧状态字节必须变化；实际相同输入可产生相同 v1 字节。已公开修正判据为“旧端跨网络接受 Duplicate＋快照无网络身份”，没有把字节不变误写成旧端安全。最终 `differential_verdict=PASS`，原始结果摘要 SHA-256 为 `958ee448c5a3882950b5d3375706c7d95aae1331c9db2c4c56982f754846492f`。

## 独立判读与跨语言勾稽

- `scripts/verify-outbox-python.py` 不用 Rust 中间结果，独立执行 UTF-8、重复键、V1 负载摘要、逐块哈希、latest 和指令来源检查；`escaped_duplicate_member` 与 `tampered_chain` 两个自证负例均被拒绝。
- Python 生成的非 ASCII 单块向量由 Rust 接受：`verified_blocks=1, verified_directives=1, untrusted_directives=0`。该向量的 `latest` 为 `87774ce37ab65262df3f5efdd331ed711104cbd9b35ab562cc94b474109d302f`。
- 判读器只覆盖无浮点且整数处于 `serde_json` 支持范围内的 V1 子集；其 canonical bytes 明确不是 RFC 8785 JCS。
- 独立运行 `jcs-canonicalize 0.2.1` 自带测试为 14／14，通过 Cyberphone 语料、UTF-16 非 BMP 键排序和 ECMAScript 数字边界等测试。**候选包未加入本仓依赖**；V1 哈希域兼容、重复键 last-value-wins、大整数舍入和版本化 V2 迁移均未因该测试而解决。

## 公网交叉验证

使用干净归档重建产物轮询七个端点，采集时刻为 2026-11-10T19:26:32Z：`asfa-ai=verified`，高度 0；cisvr／ucif2／qgl／usrm／cfts 为 HTTP 404；vinf 为 `invalid_schema`，信息为 `invalid value: map, expected map with a single key`。原始报告见 `evidence/poll-2026-11-10.json`，其 SHA-256 为 `464e24c876e111eac32bfcb123cdc605e2053115035ad8a546b6b08f2debe402`。

公网 jsDelivr 镜像与本地正本的字节和完整语义均不相等，不能宣称 `remote=local`。字段级递归对拍唯一定位到 `$.url`：

- public：`https://raw.githubusercontent.com/chepin-ai/test/main/outbox/asfa-ai-outbox.json`
- local：`https://raw.githubusercontent.com/chepin-ai/test/refs/heads/main/outbox/asfa-ai-outbox.json`

两端 `hash_chain` 完全相同，且都通过 Python 独立判读。公网镜像 SHA-256 为 `c0df0e35f63b20049ab9da97fe80509ef918ae0e3b1ad79d5e5f9ac7e36f56b4`，本地正本 SHA-256 为 `470abaed8f9641c514fcbaaa4914f6c1b879771503edcb8881b6cb21f97b77e3`。该差异实证了显式 `canonical_url` 与镜像 allowlist 仍是开放债，不能简单强制读取 URL 等于文档 URL。

## 联邦状态

最后已核验的正典状态仍为 `asfa-ai = conditional`（2026-11-09）。三项条件为 FED-JOIN 全式重报、新凭证经 KEY-SYNC-01 vault 值道注入、常备仓内通道登记。

FED-JOIN 全式重报已有投递提交 `77f9fdc678ba7239e7bffd2d4da9fd9155923f89`，但投递不等于对方 ACK 或正典升 active。旧 OTP 已永久弃用。本轮没有取得 cisvr ACK、正典升 active 或 KEY-SYNC-01 relay 完成回执；本仓 Actions Secret 写入不等于联邦中继闭环。

## 凭证、推送与外部 CI 边界

本地 remote 为 `https://github.com/chepin-ai/test.git`，不含明文凭证；秘密值不得从日志、历史文件或会话记录恢复。此前泄露的 PAT 仍应撤销／轮换，当前没有 GitHub 侧已完成撤销的证据。

本证据文件生成时，最后已知远端 `main` 为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，实现提交尚无新的外部 CI 回执。是否推送成功必须以实际推送后的 `git ls-remote` 和 local／remote 提交对拍为准；历史 run `42228729662` 只适用于旧提交 `b3b6384`，不能挪用为本轮结论。

## 明确未实现

Boot／裸机内核、WASM 沙箱、TEE、ZK-SNARK／STARK、HoTT-ZK 编译器、涌现类型系统、量子调度、神经网络推理、Holo-Lang、跨域顿悟、完整形式化安全证明。

当前 CLI 也不是后台守护进程；跨重启状态依赖显式 `--state` 或库调用方显式 `save_atomic`，没有自动 WAL。原子 rename 不提供多写者锁或 compare-and-swap，当前契约是单写者。

完整 JCS V2、发布者与指令授权、签名 checkpoint、独立 witness／quorum、多写者协调、`canonical_url`、SSRF／重定向／DNS pinning／HTTP 降级策略、可信时间、Merkle consistency proof 和后量子 witness 均未实现。

## 网络与形式化内容边界

临时 `*.ok.kimi.link` 端点只作遗留负例输入，不能作为常备通道。vinf 的 HTTP 200 不构成协议有效证据；其他 404 不推断角色离线或身份不存在。

本线仓内 JSON 是正本；jsDelivr 仅作只读镜像。镜像返回 `Verified` 只代表其内容通过当前无签名链检查，不代表镜像运营者或发布者身份已认证。

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统安全证明。历史 `Admitted` 占位文件已删除。
