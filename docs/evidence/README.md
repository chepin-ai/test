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

## 2026-11-11

- `attack-consistency-2026-11-11.json`：实现提交 `a58e5ee6f94a555dedb248f927934912ea925518` 的综合证据。干净 Git 归档＋空 target 全门禁通过，67／67 测试分解为 bridge 单元 22、bridge 集成 31、kernel 11、userspace 3；归档 SHA-256 为 `5cbb697b9601c632a61e63407667c23c518a9bdce0d3352c7bc3c2e4307e0caa`，新二进制 SHA-256 为 `398f78bc3b26760009e5192e8b25c7732b76cb8a3099e3a002327ef644660bc9`。
- `clean-rebuild-2026-11-11.log`：上述干净归档的完整重建输出；`smoke-report-2026-11-11.json` 与 `smoke-state-2026-11-11.json` 保存原始烟测报告和 v3 状态。独立 Policy Python fixture 与 live snapshot 对拍均通过。
- `differential-2026-11-11.json`：五组旧新 CLI 原始差分与预注册判据。旧端为提交 `56b351b`，新端为上述干净归档二进制；302 第二跳、canonical 错配、同网络策略替换、未知 Outbox 字段和超大 Registry 均得到预期旧新区别，`differential_verdict=PASS`。PASS 只覆盖五项判据，不是全系统安全证明。
- `poll-2026-11-11.json`：2026-11-11T03:50:56Z 的七端点原始报告。asfa-ai 为 `verified`，cfts／cisvr／qgl／ucif2／usrm 为 404，vinf 因未知字段 `chain_len` 为 `invalid_schema`。
- `poll-canonical-rejection-2026-11-11.json`：以当前公网文档和故意保留旧 `refs/heads/main` 正典的单会话 Registry 重放的负例；得到 `invalid_trust`，第二跳或身份错配不会被静默接受。
- `public-python-oracle-2026-11-11.json`：公网镜像与仓内正本的独立 Python 判读。当前两份 Outbox 字节完全相等，SHA-256 均为 `c0df0e35f63b20049ab9da97fe80509ef918ae0e3b1ad79d5e5f9ac7e36f56b4`；该相等不代表 Git 远端 main 等于本地实现提交，也不代表发布者身份认证。2026-11-10 的历史 URL 差异不回改。
- 证据生成时最后成功读回的远端 main 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，本地实现尚无新外部 CI。cisvr ACK、正典 active、KEY-SYNC-01 和旧 PAT 撤销均无完成证据；最终推送结果另以实际推送与远端读回为准。

## 2026-11-14

- `qfos-fusion-preregister-2026-11-14.json`：实现前登记的 LCK-01、SAT-01–04 与 WAVE-01–03 判据；不含结果声称。
- `attack-consistency-2026-11-14.json`：实现提交 `88a92e3778a3664f62835aa1746f21b9b831433c` 的综合证据。无 `.git`、空 target 干净重建全门禁通过，78／78 测试分解为 bridge 单元 27、bridge 集成 37、kernel 11、userspace 3；归档 SHA-256 为 `f25eefdcbd83f3bdbf8e9dcb592673d33ed39f310325dc0e45a92d8d53ea3602`，干净二进制 SHA-256 为 `e6cbf30c7cc47467696894f5ab1177f603e30ba3267e698b02be92b73ac4f2d6`。
- `clean-rebuild-2026-11-14.log`：上述归档的完整重建输出；`smoke-report-2026-11-14.json` 与 `smoke-state-2026-11-14.json` 保存原始烟测报告和状态。
- `differential-2026-11-14.json`：五组旧新进程级原始结果。pending 洪泛、tombstone 膨胀、超基数恢复、65 会话扇出及并发消费均满足预注册判据；新端使用上述干净二进制重跑。PASS 不覆盖非协作写者或分布式协调。
- `wave-oracle-2026-11-14.json`：QF-OS 静态向量的独立 Python 重建。准入为 `a1 → b1 → a2`，两个 deferred 分别对应来源和全局配额；计划哈希为 `fefb2704c277115cf4f88e2215cfb7a10cb508694a43527c300700ed47003302`，Job 与账本绑定篡改均被拒绝。该证据不是引擎执行或 QIOS 兼容证明。
- `poll-2026-11-14.json`：干净二进制于 2026-11-14T08:14:05Z 采集的七端点报告。asfa-ai 为 `verified`，cfts／cisvr／qgl／ucif2／usrm 为 404，vinf 为 `invalid_schema`。
- `public-python-oracle-2026-11-14.json`：公网镜像与仓内 Outbox 字节相等，双方 SHA-256 均为 `c0df0e35f63b20049ab9da97fe80509ef918ae0e3b1ad79d5e5f9ac7e36f56b4`，独立判读通过；不据此推导远端 Git 同步、发布者身份或联盟状态。
- 本轮远端读回出现 TLS 错误与超时；最后成功远端 main 仍为历史值 `c573dc496dc3caeab1f0f143373c80859ccd93d4`。cisvr ACK、正典 active、KEY-SYNC-01、旧 PAT 撤销和本轮外部 CI 均无完成证据；最终推送结果另以实际推送与读回为准。

### 全轮询与 JSON 资源预算续拍

- `resource-budget-preregister-2026-11-14.json`：实现前登记的 TIME-01／02 与 JSON-01／02／03 判据，不含结果声称。
- `resource-budget-consistency-2026-11-14.json`：实现提交 `33ff4a63d9dfd7e20c6d34b79296cd400d5e07f4` 的综合证据。无 `.git`、空 target 干净重建全门禁通过，85／85 测试分解为 bridge 单元 29、bridge 集成 42、kernel 11、userspace 3；归档 SHA-256 为 `f77faa8aca8395bcec297397165dde315ee96b023092f411e2b71df216ac552b`，干净二进制 SHA-256 为 `95a75c596363242c674e8b4ab1a17a6ac40a053d3d28d9b5f348b1c25b48db77`。七项 artifact 的路径、字节数与 SHA-256 已复算。
- `resource-budget-differential-2026-11-14.json`：五组旧新真实进程结果及首轮夹具 FAIL 的公开修正。TIME-01 新端在首会话耗尽总预算后非零退出，第二会话零请求且不生成报告；TIME-02 四种非法参数均在 I/O 前拒绝；JSON-01／02 旧端接受深层／超节点开放 mailbox，新端显式拒绝；JSON-03 新端在轮询前拒绝深层 Registry／Snapshot，原状态字节不变。最终 `differential_verdict=PASS`，其 SHA-256 为 `99981b538d53764dd005691c73f8c7562f911158e803e9d7083d44f2f8e77e50`。
- `resource-budget-clean-rebuild-2026-11-14.log`：上述干净归档的完整重建输出；`resource-budget-smoke.json` 与 `resource-budget-smoke-state.json` 保存原始烟测报告和状态。认知示例、Wave 计划哈希和 `total=3, verified=1, failed=2` 烟测均未漂移。
- `json-budget-oracle-2026-11-14.json`：独立 Python 以显式栈迭代复算深度与全文档节点；64 层接受、65 层拒绝、16384 节点接受、16385 节点拒绝、跨分支计数与转义重复键五个已知答案自证通过，不读取 Rust 中间结果。
- `resource-budget-poll-2026-11-14.json`：干净二进制于 2026-11-14T15:17:42Z、显式 60 秒总预算下采集的七端点报告。asfa-ai 为 `verified`，cfts／cisvr／qgl／ucif2／usrm 为 404，vinf 为 `invalid_schema`；只描述采集时点，不证明远端实现提交、发布者身份或联盟状态。
- PASS 只覆盖本轮预注册判据，不证明 DNS 完整受控、进程级内存／CPU／文件描述符隔离、分布式锁、QF-OS 执行或 QIOS 兼容。cisvr ACK、正典 active、KEY-SYNC-01、旧 PAT 撤销、远端同步和外部 CI 均无完成证据；最终推送结果另以实际推送与读回为准。

## 2026-11-16—17

- `execution-preregister-2026-11-16.json`：实现前登记的 EXE-01–06，覆盖真实内建输出、五类死信、恢复与重放、独立语义判读、v4 原子快照和旧新进程差分；不含结果声称。
- `execution-differential-2026-11-16.json`：同一 Registry／Outbox 下的九项真实进程差分，旧端提交 `320b226ca7b605f41744f50e970b2371077bebdb` 无 `--execute-wave` 且 7 项保持 pending；新端产生 2 个成功回执＋5 个死信，重放为 2＋5 skipped 且账本字节不变，独立判读通过。旧二进制 SHA-256 为 `096359978a6b4d814605687828e70d09cf3197d62f941145c5792cd02c2cfa6f`，工作树 debug 新二进制 SHA-256 为 `07444fd68cca8d9f8d49e1e2d9297fb3df777bfc1fa894db8b1e3811f2a78e24`；后者不得当作提交后干净归档二进制哈希。
- `execution-consistency-2026-11-17.json`：实现提交 `098dab63c3d449bc21a43f79d138b156624b7b15` 的综合证据。无 `.git`、空 target 干净重建全门禁通过，92／92 测试分解为 bridge 单元 32、bridge 集成 46、kernel 11、userspace 3；归档 SHA-256 为 `c645bedeb4496703417e1d47de689884d6d2089cb8e545d279ea5a9fb871bd89`，干净 debug 二进制 SHA-256 为 `a16bc5e9ea360e078def92d87da9606468771f98af027caa2546f6dedf3ceb6e`。综合证据 SHA-256 为 `6703407ff64ee27226cc197c32baf3df8d3aee3107776db866368931090401b9`，11 项 artifact 已复算。
- `execution-clean-rebuild-2026-11-17.log`：上述归档的完整重建输出；`execution-smoke-2026-11-17.json` 与 `execution-smoke-state-2026-11-17.json` 保存原始烟测报告和 v4 状态。固定计划哈希为 `f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a`，执行报告哈希为 `4cefca364f55ef97a41aeb580ab01b6c16c7a754a02acc78b23e14fc6da5a78c`，重放报告哈希为 `9dce14b4b357f72851dff2d67af085bd8c10e560aca51c414fd07ffe416be36f`。
- `execution-publication-2026-11-17.json`：记录真实发布结果。首次 push 以 TLS 非正确终止失败，随后读回超时；HTTP/1.1 重试因非交互认证不可用失败，最终读回成功且远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`。推送候选为 `7523979df84750c9f8077157ed24163c41f93719`，相对远端 `ahead_by=13, behind_by=0`；结论为 `NOT_PUSHED`、`remote≠local`，无新外部 CI，未恢复或输出历史 PAT／CMD。
- PASS 只覆盖仓内 `qfos-exec-v1`，不证明外部 QF-OS 正典、QIOS、通用 Skill 沙箱、租约、分布式 exactly-once、发布者认证、结果签名或掉电持久性。

## 2026-11-17 public-only egress 与 DNS rebinding

- `egress-preregister-2026-11-17.json`：实现前登记的 EGR-01–07，覆盖 48 条地址已知答案、旧新 loopback 差分、混合／空／超量答案、单次解析与固定拨号、有界 DNS 等待、Registry 放权注入和完整回归；不含结果声称。
- `egress-differential-2026-11-17.json`：旧端基线提交 `03cf7d8b7ee71e97fa35f25c6ab9af3ec7a3af26` 与实现提交干净归档二进制的真实进程差分。旧端 `verified／1 hit`；新默认端 `blocked_egress／0 hit`；显式本地放权目标 1 hit、恶意代理 0 hit；Registry 私加放权字段被拒绝。SHA-256 为 `9c03a0a48a56ef9607a21ea82a8f95cca030998393a034e37d8fc7528c740490`。
- `egress-consistency-2026-11-17.json`：实现提交 `32b450b01da77dab77667d930888cb201a913699` 的综合证据。无 `.git`、空 target 干净重建全门禁通过，99／99 测试分解为 bridge 单元 37、bridge 集成 48、kernel 11、userspace 3；归档 SHA-256 为 `84213d0f89ecba27c3f120c2afe82f2132dfaff1e4b79760bcbcaa2059597515`，干净 debug 二进制 SHA-256 为 `4ce77eb6ce94937c39a6fa2f5b99e4297a5a0092ed777b09e0c00453bd3898af`。综合证据 SHA-256 为 `39f0ed02005e8416e74e48c2d2b2e28343a57f942f7b394890ef04ebb3186f66`，11 项 artifact 已复算，首轮 FAIL 均保留在 `development_corrections`。
- `egress-clean-rebuild-2026-11-17.log`：上述归档的完整干净重建输出；`egress-smoke-2026-11-17.json` 与 `egress-smoke-state-2026-11-17.json` 保存对应原始烟测报告与 v4 状态。固定 wave／execution／replay 哈希与既有执行证据摘要均未漂移。
- `egress-publication-2026-11-17.json`：证据候选 `713a3608bee51b9ac44aa1728e06fdecc9b5a71c` 的真实发布边界。无凭证读回第一次成功，远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，候选 `ahead_by=15, behind_by=0`；无当前凭证，未发起认证推送，`NOT_PUSHED`，无新外部 CI。证据提交仅 amend 本记录与对应文档，分叉计数不变。
- `../scripts/verify-egress-python.py`：独立使用 Python `ipaddress` 与 CIDR 表重算 48 条地址答案，并拒绝错误状态、伪造 verified 汇总、实际发生连接和额外记录四类假报告；不是网络命名空间或形式化网络安全证明。
- `../scripts/egress-differential.py`：建立真实 loopback HTTP target／proxy、Registry 和 genesis Outbox，执行旧新进程、采集 socket hits 与报告，再交给独立判读器复核。
- PASS 只覆盖本 HTTP client 的应用层 public-only 与 rebinding 门禁；不证明底层 DNS 强制取消、线程资源隔离、外层 egress proxy、hostile OS 防护、通用 SSRF、发布者认证、外部 QF-OS／QIOS 或远端 Git 同步。

## 2026-11-21 输出路径身份与状态锁别名

- `path-preregister-2026-11-21.json`：PATH-01–07 的实现前判据、旧端实际覆盖哈希和边界；另记录 `./` 负控制已被旧端拒绝，避免把不存在的缺口包装成成果。
- `path-differential-2026-11-21.json`：八组真实旧新进程结果。poll／wave／execution 的 `sub/../state`、dangling symlink、符号链接父目录和硬链接六类攻击均为旧 exit=0、新 exit=2；新端所有声明路径 before=after 且不创建锁。dot 控制两端拒绝，distinct 控制产物字节相等。SHA-256 为 `ab87ebe30c21e84662c490466d2306f1be87cb593b3b582518157e5ed53a86ee`。
- `path-consistency-2026-11-21.json`：实现提交 `111f98a9e3d8d5f63c29d1a18228c6a2ac13cfa9` 的综合证据。104／104 测试分解为 bridge 单元 42、bridge 集成 48、kernel 11、userspace 3；干净归档 SHA-256 为 `9cf890286cdbc3b03c8d17105cc3f5dd51b865cdb5451c5b8b4c720d01d14ddd`，干净新二进制 SHA-256 为 `c8c425e8ba0dbec50ead50a0167a647d79d4967afde5510ad4d8c7c3dfde9a42`。综合证据 SHA-256 为 `82461aac0486df8ee1add33f33147a5a3f09e70fbd1762af9e260b8055e200a5`。
- `path-clean-rebuild-2026-11-21.log`：无 `.git`、空 target 的完整门禁输出；最终差分使用这次重建的新二进制，不与工作树 debug 哈希混用。
- `path-publication-2026-11-21.json`：证据候选 `759daf69ea1981753f17f23511efedce88fe1888` 的真实发布边界。2026-11-21T00:17:45+08:00 无凭证读回成功，远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，候选 `ahead_by=17, behind_by=0`；无当前凭证，未发起认证推送，`NOT_PUSHED`，无新外部 CI、cisvr ACK、KEY-SYNC-01 relay 或 active 声称。证据提交仅 amend 本记录与对应文档，分叉计数不变。
- `../scripts/verify-path-python.py`：独立 realpath／samefile／stat、文件系统 after-state 重读、五项已知答案和五类假报告自证；`../scripts/path-differential.py` 负责真实旧新进程执行。
- 首轮 dangling symlink 实现 FAIL 与独立判读器 hardlink 标签 FAIL 均保留在综合证据。PASS 不覆盖预检后恶意改名、跨进程硬链接通用锁、非协作写者、分布式协调、WAL／fsync 或远端发布状态。
