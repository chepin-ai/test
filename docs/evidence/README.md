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
- `path-publication-2026-11-21.json`：证据候选 `759daf69ea1981753f17f23511efedce88fe1888` 的历史时点发布边界。2026-11-21T00:17:45+08:00 无凭证读回成功，远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，候选 `ahead_by=17, behind_by=0`；当时未发起认证推送，`NOT_PUSHED`。该快照不回改，后续事实由 `path-push-2026-11-21.json` 追加。
- `path-push-2026-11-21.json`：后续真实推送与外部 CI 回执，只覆盖 `2a40df076c0d4f63a1f5dd25f368f2916a8d0d50`。第一枚现场凭证认证失败且无 ref 更新；第二枚单次 push exit 0，远端从 `c573dc4…` 更新到 `2a40df0…`。首次读后遇 HTTP/2 framing error，HTTP/1.1 重读后确认该提交 remote=local、ahead／behind=0。公共 Actions 列表 API 显示 run `44784042393` 的 `head_sha=2a40df0…`、`completed/success`；单 run／jobs API 后续返回 403，因此无 job 级声称。原子写实现 `46cf446…` 不属于该推送或 CI。
- `../scripts/verify-path-python.py`：独立 realpath／samefile／stat、文件系统 after-state 重读、五项已知答案和五类假报告自证；`../scripts/path-differential.py` 负责真实旧新进程执行。
- 首轮 dangling symlink 实现 FAIL 与独立判读器 hardlink 标签 FAIL 均保留在综合证据。PASS 不覆盖预检后恶意改名、跨进程硬链接通用锁、非协作写者、分布式协调、WAL／fsync 或远端发布状态。

## 2026-11-21 账本临时项独占分配与原子写攻击

- `atomic-write-preregister-2026-11-21.json`：ATOMIC-01–07 的实现前判据、基线提交与二进制锚点，以及预置 symlink 覆盖 victim 的实测；SHA-256 为 `44cd793f4898be09a0d2e8cd277955c2bef6fa3dfe9819af8e47027162244beb`。
- `atomic-write-differential-2026-11-21.json`：symlink、hardlink、regular、exhaustion、control 五组真实旧新进程结果。旧端在前三类攻击中均 exit 0 并覆盖或改名既有项；干净新端对可绕过冲突 exit 0 并保留所有 sentinel，对 128 项耗尽 exit 2、无 state 且保留全部冲突项；正常控制 state 字节相等。SHA-256 为 `04cfcf8b15494322bb528f0b4894509d9d41edf1a4fd4e140017dfd2cbff6a1d`。
- `atomic-write-consistency-2026-11-21.json`：实现提交 `46cf446b85d27e380b1771161c3c7adce70aa245` 的综合证据。106／106 测试分解为 bridge 单元 44、bridge 集成 48、kernel 11、userspace 3；干净归档 SHA-256 为 `b51dd3bf9c5ce77f5009a1ac29def11dd4aa16cc7ec0d05c7cd98a1f11a79209`，干净新二进制 SHA-256 为 `7ee25459f0eaf1825dbfc11a537783b1147137bc606065258ee391ce3ce26228`。综合证据 SHA-256 为 `502f2e2e8539aea1268d77e116d9b3f2d6df546debd1587748b08ce4d4030d2e`，七项 artifact 已复算。
- `atomic-write-clean-rebuild-2026-11-21.log`：无 `.git`、空 target 的完整门禁输出，SHA-256 为 `e4cc3aa365c6092d93999b5c7fd55e8f1ba4ae0df6da7b3f73795bf6a41a0266`；最终差分使用这次重建的新二进制。
- `../scripts/verify-atomic-write-python.py`：独立重读 path state、stat、SHA-256、schema、链接目标与文件身份，四项文件系统已知答案和五类假报告自证先于真实报告验收；`../scripts/atomic-write-differential.py` 在子进程 exec 前按真实 PID 布置精确冲突并执行五组旧新进程。
- 首次 PoC 的 `with_extension` 夹具错误没有执行目标进程，修正为 `with_suffix` 后才确认漏洞；sidecar 候选未包装成锁互斥突破。PASS 不覆盖临时项创建后至 rename 前的恶意替换、hostile OS、非协作写者、WAL／fsync、掉电持久性、分布式事务、发布者认证或 ZK 证明。

## 2026-11-21 state-lock symlink 与跨 rename inode 迁移

- `lock-symlink-preregister-2026-11-21.json`：LOCK-01–07 的实现前判据、基线提交和二进制锚点，以及真实双进程 FIFO 突破；SHA-256 为 `2a4509918509b5f39e6bc6016d85cfaa09408f8a026e61e37b50f30d3510d31b`。
- `lock-symlink-differential-2026-11-21.json`：symlink、dangling、regular、hardlink、control 五组真实旧新结果。旧 symlink 首进程存活时第二进程 exit 0、pending/consumed 6/0→5/1，lock 跟随替换后 state inode；新端 first/second 均 exit 2、state 字节和 inode 不变、FIFO 零字节。常规与 hardlink sidecar 两端均阻止跨 rename 的第二消费者；正常控制 state/report 字节相等。SHA-256 为 `402d44d240af51648f496691b116f6eb5c305bfcc7465626a15f87ee5255d99d`。
- `lock-symlink-consistency-2026-11-21.json`：实现提交 `c10d190ad9e96ed162bb46dd2f55cbd4a00ce62d` 的综合证据。109／109 测试分解为 bridge 单元 47、bridge 集成 48、kernel 11、userspace 3；干净归档 SHA-256 为 `a94032f2fe0fa0356f449b18766f32faa3bd05ab55bcac667a39a96184ed63c6`，干净新二进制 SHA-256 为 `e84ad1550f5a3d17bfaff78784460a66bf66483e30c8ad9af3357238fa65afbf`。综合证据 SHA-256 为 `e0926355e8f3c8bf56a59e062f732ec29948f55e90e75fec150e969f2b438c8d`，九项 artifact 已登记。
- `lock-symlink-clean-rebuild-2026-11-21.log`：无 `.git`、空 target 的完整门禁输出，SHA-256 为 `011b178a86305275cb30005bc977aa5935021d4de85f5d67b2eb9485d40f7279`；最终差分使用这次重建的新二进制。
- `lock-symlink-collaboration-2026-11-21.json`：本地协作卡与一次真实公共 nonce-only dispatch 的负结果。传输 exit 0，但 HTTP 401／`Requires authentication`，结论为 `NOT_DELIVERED`；cisvr、usrm、vinf、ucif2、qgl、cfts、qtlv、lgt、qlv、lvlu 十线均为 `ACK=NONE`，总判定为 `LOCAL_CARD_AND_REAL_NEGATIVE_DISPATCH_ONLY`。证据 SHA-256 为 `2fe7772fa8e0bc1b0f6c22f84aed8e4a83a954f816a882c1eae9aeeb5071f471`；本地卡片不等于送达，更不等于 ACK。
- `lock-symlink-publication-2026-11-21.json`：证据候选 `9d220eedebc9e4f05e43e03e950fa0b724ed60c3` 的发布边界。2026-11-21T05:28:52+08:00 经 TLS 失败后的 HTTP/1.1 重试读回成功，唯一允许远端 `main` 仍为 `2a40df076c0d4f63a1f5dd25f368f2916a8d0d50`，候选 `ahead_by=4, behind_by=0`；无新鲜一次一钥，未发起认证推送，结论为 `NOT_PUSHED`。旧 run `44784042393` 不覆盖本轮实现或证据候选。记录 SHA-256 为 `68841e31a7f1d88ca6e79dd63cf02dbfef818927cb85c1129c0d11ae0f7892ce`；发布记录及索引 amend 后分叉计数不变，最终 HEAD 以 Git 实测为准。
- `../scripts/verify-lock-symlink-python.py`：独立重读进程 liveness、FIFO 字节、v4 pending/consumed、链接目标、inode 和 SHA-256，并检查 Unix `O_NOFOLLOW` 位于实际 open 之前；五项已知答案和六类假报告拒绝先于真实报告验收。`../scripts/lock-symlink-differential.py` 执行真实双 CLI 与五组旧新差分。
- 夹具与判读器开发纠偏均保留在综合证据。PASS 不覆盖取得锁后的常规 lock pathname 替换、非 Unix check/open 竞态、非协作写者、hostile OS、跨主机锁、WAL／fsync、掉电持久性、外部协作投递／ACK、远端同步、发布者认证或 ZK 证明。

## 2026-11-21 一次性任务票最终证据

`ticket-utxo-preregister-2026-11-21.json` 仍是不可改写的预登记，不是结果证据。最终实现提交为 `36cf105b6685f0516c9b7aaedcecfbb6c36e6380`，基线提交为 `a4365f38ae6e47e0a014077a7c74745c20ca657b`。

最终差分使用：

- 干净重建新二进制：`c24b0c64e8629f6edb845ca4234cd3b0620d71bf0b1f95bb6edbc114dfd4e493`；
- 同基线提交重建旧二进制：`8b0ca400d0cf656d7e450d02487c4ce380f97f5f69e985256b827259bde75017`。

环境重置后，预登记中的原旧二进制 `409a500eb31b7a1bb88c2cdf14e2da48f253db95408ef07641431062fd2dc152` 已消失，**未参与最终差分**。新旧哈希差异如实保留，不回写预登记、不声称复用了原字节。

| 文件 | SHA-256 | 内容 |
|---|---|---|
| `ticket-utxo-differential-2026-11-21.json` | `24b9c74ce3186dbe11076f74e801b8440dbfeca2ef1e3d27dfd7a235ad98495e` | 九组真实旧新 CLI 差分，48 个进程步骤，含原始伪造快照 |
| `ticket-utxo-consistency-2026-11-21.json` | `9d5d8a4731da28e2f32a95bca532458012bb4f76e54e18fa1553629d435fe0c8` | 独立判读 PASS；伪造真实报告在验收前拒绝 |
| `ticket-utxo-state-verdict-2026-11-21.json` | `b890856c162be306b1a3e9085f3d5f142f1277591257bf545e9fbf6143919218` | 最终 v5 状态独立 PASS |
| `clean-build-all.log` | `887b5c1d1a2aff5a07fc5e0095c46db3502e6725e5b8a7d1689519379f9349d5` | 无 `.git`、空 target 实现归档的完整构建与门禁 |
| `old-baseline-build.log` | `3221df40538c8575392a561905dd79b462be680a4f0d4475c4b4cbad6f90d886` | 基线提交旧二进制重建 |
| `clean-rebuild-environment.txt` | `df9f9608fe0a86a295d0ecc5dea3800c41e1deb761d3c9d226a24c6c66b61b12` | 提交、工具链、干净目录与实现归档哈希 |
| `artifact-sha256.txt` | `7f1605cf313fa013d7bab33ab283182847d2ab44671750f62388333dcf643175` | 执行时原始哈希清单，保留沙箱绝对路径 |

独立复核：

```bash
python3 scripts/verify-ticket-utxo-python.py --self-test
python3 scripts/verify-ticket-utxo-python.py \
  --report docs/evidence/ticket-utxo-differential-2026-11-21.json \
  --out /tmp/ticket-consistency-recheck.json
cmp /tmp/ticket-consistency-recheck.json \
  docs/evidence/ticket-utxo-consistency-2026-11-21.json
```

判读器自证为 3 个已知答案、1 个合成有效、4 个合成拒绝；真实报告为 9 组、48 个进程步骤。总索引 `ticket-utxo-evidence-manifest-2026-11-21.json` 另登记实际二进制、实现归档和边界。证据只覆盖本地能力授权、完整性、恢复与重放，不是签名／witness／ZK、发布者认证、分布式 exactly-once 或 hostile writer 防护证明。文章来源仍为二手技术报告，未获得原始 Kiki 实现。

- `ticket-utxo-publication-2026-11-21.json`：证据候选 `5469b52424316521de90c8bd3b730bfbc39590ae` 的发布边界。两次 `ls-remote` TLS 终止后，以 GitHub 公共 API 确认远端 `main=2a40df076c0d4f63a1f5dd25f368f2916a8d0d50`，`ahead_by=6, behind_by=0`；未复用凭证、未推送，结论 `NOT_PUSHED`，无新外部 CI 或联邦 ACK。发布记录与索引 amend 后最终 HEAD 以 Git 实测为准。
