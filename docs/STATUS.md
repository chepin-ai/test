# 实现状态（本轮实测证据：2026-11-11）

## 已有实测

- 稳定版 Rust 工作区可编译；实现提交为 `a58e5ee6f94a555dedb248f927934912ea925518`。
- 67 个 Rust 单元／集成测试通过：bridge 单元 22、bridge 集成 31、kernel 11、userspace 3，失败为 0。
- 从该实现的 Git 归档解到无 `.git` 的干净目录，并使用空 `CARGO_TARGET_DIR` 完整执行 `scripts/build-all.sh`。格式检查、Clippy 零警告、67 项测试、凭据扫描、Outbox／Policy Python 独立判读及负例自证、认知示例精确契约和 CLI 烟测均通过。归档 SHA-256 为 `5cbb697b9601c632a61e63407667c23c518a9bdce0d3352c7bc3c2e4307e0caa`，干净重建二进制 SHA-256 为 `398f78bc3b26760009e5192e8b25c7732b76cb8a3099e3a002327ef644660bc9`。
- 认知示例精确输出为 `skill_output={"sum":42}; edge=1; matches=[1]`。CLI 烟测为 `total=3, verified=1, failed=2`，两个失败是故意设置的非法 JSON 和缺失文件；v3 烟测状态的独立 Python 策略对拍通过，摘要为 `d7bb090c4022b10a3f46ca236315cd96a77091ca0edeac038fac4016245d6a19`。
- 综合机器可读证据见 `evidence/attack-consistency-2026-11-11.json`，其 SHA-256 为 `c60577c7fb78cc9500ecebeeb426e553e243e03bd43e05d96e133c8980385a42`；原始差分、重建日志、公网报告与判读结果均单独落盘。攻击、规范映射与未覆盖边界见 `ISOMORPHISM_ATTACK_MATRIX.md`。

## 本轮新增安全性质

1. **重定向显式失败**：HTTP client 禁止自动重定向，300–399 均产生 `http_status` 负结果；302 负例中第二跳命中数为 0。
2. **正典 URL 绑定**：`Outbox.url` 必须精确等于会话 `canonical_url`；未配置时默认等于读取 URL。显式配置后只读镜像地址可与正典地址不同，但不因此获得发布者或镜像身份认证。
3. **传输显式授权**：默认只接受 HTTPS；HTTP 与 file 分别要求 `allow_insecure_http=true` 和 `allow_file=true`。其他 scheme、fragment、HTTP(S) 缺失 host 与 userinfo 在 I/O 前拒绝。
4. **封闭协议 schema**：Outbox、Registry、LedgerSnapshot 等核心协议结构拒绝未知字段，避免把未知扩展静默解释成安全语义；`mailbox` 与区块 `payload` 仍为开放数据。
5. **网络＋安全策略联合绑定**：账本升级为 `asfa-directive-ledger/v3`，保存并复核 `network_name` 与 `policy_hash`。旧 v1／v2、跨网络或同网络不同安全策略的状态不隐式迁移；只改 `role`／`note` 保持兼容。
6. **有界输入**：Outbox 与 Registry 上限均为 2 MiB，Snapshot 上限 16 MiB；文件同时检查 metadata 与实际读回字节。256 层嵌套负例失败关闭，但应用自定义深度／节点预算仍未实现。
7. **独立策略判读**：Python 从原始 Registry 重建安全投影与 SHA-256，和 Rust 已知答案一致；说明字段与显式默认 canonical 不改变摘要，URL 变化必须改变摘要。

既有严格重复键拒绝、每会话 `(height,latest)` 检查点、完整验链后才入库和零部分应用继续有效。策略摘要与检查点只覆盖本机已有视图，不是签名、Merkle consistency proof 或外部 witness；整份状态文件被旧快照替换仍需外部单调锚或独立 quorum。

## 旧新 CLI 差分

旧实现提交为 `56b351b82b04967ce9118590f34f0405596f6362`，新实现提交为 `a58e5ee6f94a555dedb248f927934912ea925518`。两端均从各自 Git 归档构建；新端二进制与上述干净全门禁、公网轮询使用同一 SHA-256。五组真实进程级 A/B 均通过预注册差分判据：

| 输入 | 旧端实测 | 新端实测 |
|---|---|---|
| 302 指向第二跳 | 返回 0，第二跳命中 1，`verified` | 返回 0，第二跳命中 0，`http_status=302` |
| 正典 URL 错配 | 忽略声明的 canonical，返回 0，`verified` | 返回 0，`invalid_trust`，明确报告 mismatch |
| 同网络替换读取策略 | 第二次返回 0，复用状态并报 `duplicate=1` | 第二次返回 2，`ledger policy mismatch`，状态字节不变且不生成报告 |
| 未知 Outbox 字段 `trusted` | 返回 0，`verified` | 返回 0，`invalid_schema: unknown field trusted` |
| Registry 超过 2 MiB | 返回 0，生成 state／report 并 `verified` | 返回 2，报超过 2097152 字节，state／report 均不创建 |

原始结果见 `evidence/differential-2026-11-11.json`，SHA-256 为 `0536d54b3c99a549a72aee2cba7cc9e15d7095fdd314589131613e56c5e29638`。独立断言与 `differential_verdict=PASS` 只表示五项预注册旧新区别成立，不是全系统安全证明。

早期 harness 曾把 config 与 outbox 写成同一路径，产生与目标漏洞无关的 missing-session 错误；分离文件名后全部重采。零高度策略用例也曾只显示 checkpoint 复用，最终改用真实单块指令，使旧端跨策略 `duplicate=1` 与新端策略拒绝都可观测。修正记录已写入综合证据，未把 harness 错误当安全结论。

## 独立判读与跨语言勾稽

- `scripts/verify-outbox-python.py` 独立执行 UTF-8、重复键、V1 负载摘要、逐块哈希、latest 和指令来源检查；`escaped_duplicate_member` 与 `tampered_chain` 两个自证负例均被拒绝。它只覆盖无浮点且整数处于 `serde_json` 支持范围内的 V1 子集，不是 RFC 8785 JCS。
- 非 ASCII 单块向量继续由 Rust 与 Python 双方接受，`latest` 为 `87774ce37ab65262df3f5efdd331ed711104cbd9b35ab562cc94b474109d302f`。
- `scripts/verify-policy-python.py` 的 fixture 摘要为 `d5805bd450f0778f996fd6094d3a1723114da35be1adee5ca8bd0f361a3c7a21`，Rust 集成测试与 Python 独立重算一致；三项自证及 live v3 snapshot 对拍均通过。
- 策略投影包含 Registry 版本、网络、trust model 及每会话 URL、解析后 canonical、trust 和两个传输授权布尔值；`role`／`note` 明确排除。省略 canonical 与显式填写相同读取 URL 具有相同投影。

## 公网交叉验证

使用干净归档重建产物，于 2026-11-11T03:50:56Z 轮询七个端点：`asfa-ai=verified`，高度 0；cisvr／ucif2／qgl／usrm／cfts 为 HTTP 404；vinf 为 `invalid_schema`，信息为未知字段 `chain_len`。原始报告见 `evidence/poll-2026-11-11.json`，SHA-256 为 `e4da71748ea546ed768f7671f12e8543e57a1f2a70fccfb4cf54b770e7d14c6d`。

另以同一二进制和当前公网文档执行单会话负例：故意把 Registry 正典保留为旧 `refs/heads/main` 形式，于 2026-11-11T03:50:59Z 得到 `total=1, verified=0, failed=1` 和 `invalid_trust: canonical URL mismatch`。该报告见 `evidence/poll-canonical-rejection-2026-11-11.json`，不是伪造的历史采集记录。

当前公网 jsDelivr 镜像与仓内正本的 Outbox 字节完全相等，`cmp` 通过，双方 SHA-256 均为 `c0df0e35f63b20049ab9da97fe80509ef918ae0e3b1ad79d5e5f9ac7e36f56b4`；两份字节均通过 Python 独立判读。该相等只针对当前 Outbox 内容：**Git 远端 main 与本地实现提交并不相等**，镜像 `verified` 也不认证发布者。2026-11-10 的 `$.url` 历史差异保留在旧证据中，不回改。

## 联邦状态

最后已核验的正典状态仍为历史记录 `asfa-ai = conditional`（2026-11-09）。本轮没有取得 cisvr ACK、正典升 active 或 KEY-SYNC-01 relay 完成回执；本仓 Actions Secret 写入不等于联邦中继闭环。旧 OTP 永久弃用，写入 outbox 文件不等于真实投递，更不等于对方 ACK。

## 凭证、推送与外部 CI 边界

本地 remote 为 `https://github.com/chepin-ai/test.git`，不含明文凭证；秘密值不得从日志、历史文件或会话记录恢复。此前泄露的 PAT 仍应撤销／轮换，当前没有 GitHub 侧已完成撤销的证据。

证据生成时，最后成功读回的远端 `main` 为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，与本地实现提交 `a58e5ee6f94a555dedb248f927934912ea925518` 不相等；实现提交没有新的外部 CI 回执。后续是否推送成功必须以实际推送后的 `git ls-remote` 和 local／remote 提交对拍为准；历史 run `42228729662` 只适用于旧提交 `b3b6384`，不能挪用为本轮结论。

## 明确未实现与后续债

Boot／裸机内核、WASM 沙箱、TEE、ZK-SNARK／STARK、HoTT-ZK 编译器、涌现类型系统、量子调度、神经网络推理、Holo-Lang、跨域顿悟、完整形式化安全证明均未实现。当前 CLI 也不是后台守护进程；跨重启状态依赖显式 `--state` 或库调用方显式 `save_atomic`，没有自动 WAL。

后续债按攻击面保留：

1. DNS rebinding／pinning、解析器意见不一致、连接时 IP 绑定和 DNS 超时覆盖；
2. 私网、loopback、link-local、cloud metadata 地址策略与外层 egress 隔离；
3. Registry session 数、全轮询总 deadline、扇出及 JSON 深度／节点预算；
4. 多写者锁、CAS、WAL 和原子 check-and-persist；
5. 整份快照回滚、分裂视图、签名 checkpoint、独立 witness／quorum；
6. 发布者与指令授权、可信时间；
7. 完整 JCS V2、Merkle consistency proof、后量子 witness；
8. 联盟 active、cisvr ACK、KEY-SYNC-01 和旧 PAT 撤销的外部回执。

原子 rename 不提供多写者互斥，禁重定向不等于完整 SSRF 防护，2 MiB 上限也不替代结构性资源预算。

## 网络与形式化内容边界

临时 `*.ok.kimi.link` 端点只作遗留负例输入，不能作为常备通道。vinf 的 HTTP 200 不构成协议有效证据；其他 404 不推断角色离线或身份不存在。

本线仓内 JSON 是正本；jsDelivr 仅作只读镜像。镜像返回 `Verified` 只代表其内容通过当前无签名链检查，不代表镜像运营者或发布者身份已认证。

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统安全证明。历史 `Admitted` 占位文件已删除。
