# 实现状态（本轮实测证据：2026-11-16—23）

## 最新续拍：身份广播、QFA 映射与跨线外部 CI

- ASFA 私域身份／证据宿主已建立并验证为 `chepin-ai/asfa-ai`，代号 `asfa-ai`；唯一公共代码远端仍为 `chepin-ai/test`。8 个有效密钥槽已密封写入 ASFA 私仓并逐项元数据回读，值不入文本。
- chepin-ai 的 QFA 公域塔为 `vci-qfa`，QI-OS origin 为 `qfa-ai`；当前 AI-FULL 仓谱未见 chepin-ai 的 QFA 私仓匹配。跨账户私有实现只在私域讨论件登记。完整映射与广播回执见 `ASFA_QFA_IDENTITY.md`。
- QI-OS 大周天扩至 14/14 `DELIVERED`，新增 qgl／ucif2／vinf，既有 11 单不重发。usrm 与 qfa-ai 各有 1 份唯一 `OPEN` 答件被接受，18 份重复答件全部 `ANSWER_IMMUTABLE`；独立 crosscheck 已为两线各建立 1 份且均为 `OPEN`，全局研究仍不晋级。
- 跨线落实：usrm 与 QFA responder 已支持由 `AI_FULL_PAT` 承载的规范答件；随后修复认证答件反馈环。规范答件 E2E run 为 `45284008539`／`45284023261`，环闸 run 为 `45286403540`／`45286410920`，均成功；环闸显式 skip 且不新增答件。
- 独立判读已区分 `protocol_answers_seen=22`、`unique_answers_accepted=2`、`independent_crosschecks=2` 和 `duplicate_answer_rejections=18`，不再把线上重复评论虚增为独立成果。QI 公共 CI crosscheck run 为 `45289708599`／`45289712612`，两份复核均绑定首答摘要、异身份主体且结论 `OPEN`。
- QI-OS HMAC 传输与 crosscheck 攻击回归为 140/140：弱关联只放行签名候选，实际接受仍需正钥；错钥、错事件 ID、错摘要、同主体、重复复核及 OPEN 晋级均被拒绝。
- 构建债修复：`702de82` 的外部 Rust CI 因 RsProxy 504 连续失败两次；移除仓级强制镜像替换，恢复标准 crates.io sparse registry，锁文件和测试判据不变，由后续空缓存 CI 判定。

## 2026-11-23：QI-OS 全局大周天真实投递与独立读回（历史快照）

- 实现提交为 `de700418f5adc7f49a85410b3f0a05e3ac926999`。直接复用 QI-OS 原生工单、答件、append-only 账本和异身份 crosscheck，新增 Lean 野问与 usrm peer，不另造共识语义，也不把 QI-OS 运输判词当作 Lean 证明。
- QI-OS 原始提交 `c13dcee8f67fce568e8b160be39c3d6ff8755736` 独立归档测试 128 项通过；加入 usrm 后，将两处硬编码线路数断言改为配置驱动，完整 128 项再次通过。fresh prepare 初版继承历史 runtime 的 21 订单异常在网络发送前修复，最终新实例为 11 单。
- 11 个工单全部 `DELIVERED`，含 usrm #24、cisvr #2、federation #18。独立在线判读逐一重算标题与 canonical body，11/11 一致，哈希链完整，`accepted_answers=0、promotion=false、research_verdict=OPEN`。
- usrm 自动回复存在，但作者关联为 `CONTRIBUTOR` 且不是合法 `QI-OS-ANSWER-V1` 事件，故不计 ACK；修正单已写入 usrm #24 与 cisvr #2 并读回一致。usrm 后续 comment `7100156572` 已确认修正口径，但明确标为非协议答件，仍不晋级；管理卡包含协议标记导致自身列为 invalid 的异常也已登记。全局共识和各线完成均未成立。
- `AI_FULL_PAT` 经公共 run `45165978216` 实测认证为 `chepin-ai`。有效 QI／Kaggle／Deepseek／Kimi 值已密封写入私域 Secrets，11 个写入均元数据回读；BI 与 Gitee 401，未覆盖旧槽位。私域完整证据初提交为 `c00b8629713b4faea667377fe079ebfacc68d8af`，最新响应增补为 `6f9f5690c3283e6dec46f28f820d08f6c202491b`。
- 从实现提交归档重跑：119 项 Rust 测试、Lean 6 声明／6 attestations／36 投影、QI-OS fresh prepare 与独立自证全部通过。公开证据总索引为 `evidence/qios-wave-evidence-manifest-2026-11-23.json`，私仓名、私钥值和私有投递明细不公域扩散。

## 2026-11-23：Lean 证据联邦最小垂直切片

- 实现提交为 `280d62f3e2225ac7ea314b4492aa51d78a32f6a8`，基线为 `04166e8974583594ff20990d8fa7920c91c0c78a`。采用 Lean 证明核＋HOLO 血缘核＋Lake 多包版本列车＋事件驱动联邦，不以单一巨包、隐式升级或最后写入覆盖强求全局一致。
- 从实现提交归档，在无 `.git`、空 Rust target、空 Lean `.lake` 环境重跑：119 项 Rust 测试及既有全部门禁保持；Lean `v4.35.0` 实际构建和公理审计通过，六个定理只依赖 `propext`，形成 6 个声明、6 个 attestation 和 36 个精确／有损投影。
- 独立 Python 判读先通过 8 个关系已知答案、2 个合成有效、4 个合成拒绝和 3 个投影边界，再验收真实报告为 PASS；同键异命题冲突零写入、重放字节不变、语义伪造报告在验收前被拒绝。证据总索引为 `evidence/lean-federation-evidence-manifest-2026-11-23.json`。
- 当前仅为本线 `FORMAL_R1`。官方 `lake check` 因 `bwrap` 无法创建 `/run/user` 而在检查前失败，未使用非隔离绕行；独立内核、跨机重放和 R2 均未建立。usrm 公共包保持 `v4.9.0` 与 `REGISTERED_NOT_ACTIVATED`，未强行迁移。
- 协作 nonce 为 `QF-LEAN-FED-20261123-01`。cisvr 与 usrm 的真实 API dispatch 均返回 HTTP 401，全部请求线路为 `NOT_DELIVERED／ACK=NONE`；本地责任单、请求和负回执已入仓，不能声称全局讨论、跨线响应或外部 CI 已发生。

## 2026-11-23：旧执行／任务票混合模式失败关闭

- 实现提交为 `88e01c894b88773fe5a5f89bac54b285c9d02f1c`，基线为 `42e040c82ad22b9de34c42c6438641ef09eea9f7`。CLI 在参数解析阶段拒绝 `--execute-wave` 与 Mint／Transfer／Revoke 同用，阻断“旧执行结果已写入、票状态也变更、但没有任务票 Execute 交易”的混合历史。单独旧执行、单独票变更和 `--execute-wave --ticketed-execution` 的既有契约不变。
- 从实现提交归档在无 `.git`、初始无 target 环境完整重建，119 项 Rust 测试通过：bridge 单元 56、bridge 集成 49、kernel 11、userspace 3；格式、Clippy、秘密扫描、独立 Python 自证、固定 v4／v5、执行重放、认知示例和 smoke 均通过。
- 最终差分为 5 组、17 个真实进程步骤：旧端复现 Transfer／Revoke 两类混合历史，干净重建新端在副作用前拒绝且零输出；独立判读 `PASS`，伪造真实报告在验收前被拒绝。证据总索引为 `evidence/ticket-mixed-mode-evidence-manifest-2026-11-23.json`。
- 探索性复现先于登记，预注册保持 `AFTER_EXPLORATORY_REPRO_BEFORE_FIX` 和 `PREREGISTERED_ONLY`。`ANOMALY-1` 明确：Transfer 混合态可在原结果时间戳被吸收，不是永久不可恢复；Revoke 混合态仍因根失活不能经任务票接口恢复。
- 本地 PASS 不等于推送、外部 CI、发布者认证、签名 witness、ZK、分布式 exactly-once 或联邦 ACK。最终发布边界见 `evidence/ticket-mixed-mode-publication-2026-11-23.json`。

## 2026-11-21：一次性任务票与 v5 恢复闭环（历史证据）

- 实现提交为 `36cf105b6685f0516c9b7aaedcecfbb6c36e6380`（`feat(bridge): bind wave execution to single-use capability tickets`），基线为 `a4365f38ae6e47e0a014077a7c74745c20ca657b`。Mint 创建根控制票与逐作业工作票；Transfer、Revoke、Execute、重放和恢复均校验单次消费、唯一作业链、plan 绑定、根预算与执行结果血缘。
- 从实现提交的 Git 归档在无 `.git`、初始无 target 环境完整重建，118 个 Rust 测试通过：bridge 单元 56、bridge 集成 48、kernel 11、userspace 3；其中 ticket 模块 9 项。完整 `build-all`、rustfmt、Clippy、独立判读、固定夹具、执行重放、认知示例与 CLI 烟测均通过。
- 最终差分使用干净新二进制 `c24b0c64e8629f6edb845ca4234cd3b0620d71bf0b1f95bb6edbc114dfd4e493` 与同基线提交重建旧二进制 `8b0ca400d0cf656d7e450d02487c4ce380f97f5f69e985256b827259bde75017`。原预注册旧二进制 `409a500eb31b7a1bb88c2cdf14e2da48f253db95408ef07641431062fd2dc152` 因环境重置消失，未参与最终差分；哈希差异不回写预登记。
- 独立 Python 判读器先通过 3 个已知答案、1 个合成有效、4 个合成拒绝，并在验收前拒绝伪造真实报告；最终 9 组、48 个真实进程步骤 verdict 为 PASS。最终 v5 状态票账本哈希为 `75e657fb8119056491d1893a9f025c89f0b20bfaff7acef172ea65fae7b7c733`。证据总索引为 `evidence/ticket-utxo-evidence-manifest-2026-11-21.json`。
- 根撤销恢复不变量由 Rust 与独立 Python 同时实现：任一 Transfer／Execute 不得位于根 Revoke 同一时间或之后，相同时间失败关闭。多作业只支持全部当前工作票链尖同属一个接收人的整波执行，当前没有拆波接口。
- 哈希不是签名／witness／ZK。PASS 不覆盖发布者认证、非协作写者、hostile OS、跨主机锁、分布式 CAS、WAL／fsync、掉电持久性、分布式 exactly-once、共识或外部结算；文章来源仍为二手技术报告，未获得原始 Kiki 实现。证据入仓不等于公开仓推送、外部 CI 或联邦 ACK。

## 2026-11-21 state-lock symlink 与跨 rename inode 迁移闭环（历史证据）

- 实现提交为 `c10d190ad9e96ed162bb46dd2f55cbd4a00ce62d`（`fix(bridge): reject symbolic-link state locks`），基线为 `be95cba53c25cd04e1f1dd25fe437a09f6a9f2bd`。旧端真实双 CLI 实测：预置 `<state>.lock -> state.json` 后，首进程在原子替换 state 后阻断于 FIFO 且仍存活；第二进程却 exit 0 并消费 `exec/sum`，pending/consumed 从 6/0 变为 5/1，lock symlink 已指向替换后的 state inode。
- 新实现以可移植 `symlink_metadata` 预检显式拒绝预置最终／dangling lock symlink，Unix 实际 open 使用 `O_NOFOLLOW`。新端两个攻击进程均 exit 2，无轮询完成、消费、状态变化或报告输出，初始 state 字节与 inode 不变，dangling target 不创建。
- 常规 sidecar 与预置 hardlink sidecar 的旧新对照均在首进程存活、state 已 rename 时让第二进程 exit 2；常规 sidecar 保持独立 inode，hardlink sidecar 保持初始 state inode而不迁移。正常控制旧新 state／report 字节分别相等。
- 从实现提交的 Git 归档在无 `.git`、空 target 环境完整重建，109 个 Rust 测试通过：bridge 单元 47、bridge 集成 48、kernel 11、userspace 3；rustfmt、Clippy、凭据扫描、九类独立判读、固定夹具、执行重放、认知示例和 CLI 烟测全部通过。干净 tar SHA-256 为 `a94032f2fe0fa0356f449b18766f32faa3bd05ab55bcac667a39a96184ed63c6`，干净新二进制 SHA-256 为 `e84ad1550f5a3d17bfaff78784460a66bf66483e30c8ad9af3357238fa65afbf`。
- 最终五组差分使用该干净二进制，原始报告 SHA-256 为 `402d44d240af51648f496691b116f6eb5c305bfcc7465626a15f87ee5255d99d`。独立 `verify-lock-symlink-python.py` 复核进程 liveness、FIFO、schema、链接目标、inode 与 SHA-256；五项文件系统已知答案和六类假报告拒绝先于真实报告验收。综合证据为 `evidence/lock-symlink-consistency-2026-11-21.json`，SHA-256 为 `e0926355e8f3c8bf56a59e062f732ec29948f55e90e75fec150e969f2b438c8d`。
- 协作面只生成了本地 nonce-only 卡片并执行一次真实公共 dispatch：传输 exit 0，但 HTTP 401／`Requires authentication`，故为 `NOT_DELIVERED`；cisvr、usrm、vinf、ucif2、qgl、cfts、qtlv、lgt、qlv、lvlu 十线均为 `ACK=NONE`，没有 lvlu 回应或 cisvr ACK。原始记录为 `evidence/lock-symlink-collaboration-2026-11-21.json`，SHA-256 为 `2fe7772fa8e0bc1b0f6c22f84aed8e4a83a954f816a882c1eae9aeeb5071f471`；本地卡片未包装成广播或送达。
- 发布边界实测：证据候选 `9d220eedebc9e4f05e43e03e950fa0b724ed60c3` 相对唯一允许远端 `main=2a40df076c0d4f63a1f5dd25f368f2916a8d0d50` 为 `ahead_by=4, behind_by=0`，故 `remote≠local`、`NOT_PUSHED`。无新鲜一次一钥，未发起认证推送或复用已消费凭证；旧推送及成功 run `44784042393` 只覆盖 `2a40df0…`，不覆盖本轮实现或证据候选，也没有本轮新外部 CI 证据。原始记录为 `evidence/lock-symlink-publication-2026-11-21.json`，SHA-256 为 `68841e31a7f1d88ca6e79dd63cf02dbfef818927cb85c1129c0d11ae0f7892ce`。
- 夹具字段／计数、Registry 策略身份、判读器 inode 与 hardlink 锚点的开发纠偏均保留在综合证据。PASS 不覆盖取得锁后的常规 lock pathname 替换、非 Unix check/open 竞态、非协作写者、hostile OS、跨主机锁、CAS、WAL／fsync、掉电持久性或临时项创建后竞态；本地通过也不是外部投递、ACK、推送、CI、外部 QF-OS／QIOS、签名 witness 或 ZK 证明。

## 2026-11-21 账本临时项独占分配与原子写攻击闭环（历史证据）

- 实现提交为 `46cf446b85d27e380b1771161c3c7adce70aa245`（`fix(ledger): allocate snapshot temporaries exclusively`），基线为 `2a40df076c0d4f63a1f5dd25f368f2916a8d0d50`。基线真实进程实测：在 exec 前预置 `state.tmp-<pid>-1` symlink，旧端 exit 0，sentinel victim 被覆盖为 v4 账本，最终 state 成为指向 victim 的 symlink；hardlink 与普通文件冲突也可被旧端覆盖或改名。
- 新实现以 `OpenOptions::write(true).create_new(true)` 独占分配每个临时候选，预置链接或文件只计为 `AlreadyExists`；最多尝试 128 个候选，其他 I/O 错误立即返回，写入、rename 与清理错误显式上报。可绕过冲突时安全成功，128 项全部占用时 exit 2、无 state 且全部 sentinel 保留。
- 从实现提交的 Git 归档在无 `.git`、空 target 环境完整重建，106 个 Rust 测试通过：bridge 单元 44、bridge 集成 48、kernel 11、userspace 3，失败为 0；rustfmt、Clippy、凭据扫描、八类独立判读、固定夹具、执行重放、认知示例和 CLI 烟测全部通过。
- 干净 tar 归档 SHA-256 为 `b51dd3bf9c5ce77f5009a1ac29def11dd4aa16cc7ec0d05c7cd98a1f11a79209`，干净 debug 新二进制 SHA-256 为 `7ee25459f0eaf1825dbfc11a537783b1147137bc606065258ee391ce3ce26228`，旧基线二进制 SHA-256 为 `7d17536d82cadd784ae6f9d9def2d53708d44eb906449522ca1067ad7c0cef5d`。最终五组差分使用该干净新二进制：symlink／hardlink／regular／control 新端 exit 0，exhaustion 新端 exit 2；原始报告 SHA-256 为 `04cfcf8b15494322bb528f0b4894509d9d41edf1a4fd4e140017dfd2cbff6a1d`。
- 独立 `verify-atomic-write-python.py` 从记录的子进程 PID 重建精确临时名，使用 path state／stat／SHA-256／JSON schema／链接目标／文件身份重算每个 after-state；四项文件系统已知答案与五类假报告拒绝先于真实报告验收。综合证据为 `evidence/atomic-write-consistency-2026-11-21.json`，SHA-256 为 `502f2e2e8539aea1268d77e116d9b3f2d6df546debd1587748b08ce4d4030d2e`，ATOMIC-01–07 全部 PASS，七项 artifact 已复算。
- 首次 PoC 的 Python `with_extension` 夹具错误未执行目标进程，修正为 `with_suffix` 后才确认漏洞；state-lock sidecar 候选经审计不构成锁 inode 替换，未包装成突破。两项均保留在 `development_corrections`。
- 本轮只关闭预置临时项攻击。临时项成功创建后至 rename 前的恶意替换、hostile OS、非协作写者、WAL／fsync、掉电持久性、CAS、分布式协调、外部 QF-OS／QIOS、签名 witness 与 ZK 证明仍未获得；该实现及后续证据提交未被上一轮推送或外部 CI 覆盖。

## 2026-11-21 输出路径身份与状态锁别名闭环（历史证据）

- 实现提交为 `111f98a9e3d8d5f63c29d1a18228c6a2ac13cfa9`（`fix(bridge): reject aliased output paths before writes`），基线为 `4ae57d5106b2f46dc0579e58520766abe4a9df46`。基线实测确认：`existing-subdirectory/../state`、dangling symlink、符号链接父目录和硬链接绕过旧词法检查；旧端在轮询、wave 和 execution 三条链上均以 exit=0 覆盖目标。单纯 `./` 已被旧端拒绝，不作为漏洞成果。
- 新实现把 `--state`、`--out`、`--wave-out`、`--execution-out` 统一在任何锁、轮询、执行和写入前解析并判重。已存在输出还比较 Unix device/inode 或 Windows volume/file index；状态锁从解析后的状态目标派生，最终 symlink 与直接路径竞争同一 sidecar。
- 从实现提交的 Git 归档在无 `.git`、空 target 环境完整重建，104 个 Rust 测试通过：bridge 单元 42、bridge 集成 48、kernel 11、userspace 3，失败为 0；rustfmt、Clippy、凭据扫描、七类独立判读、固定夹具、执行重放、认知示例和 CLI 烟测全部通过。
- 干净 tar 归档 SHA-256 为 `9cf890286cdbc3b03c8d17105cc3f5dd51b865cdb5451c5b8b4c720d01d14ddd`，干净 debug 新二进制 SHA-256 为 `c8c425e8ba0dbec50ead50a0167a647d79d4967afde5510ad4d8c7c3dfde9a42`。八组旧新差分由该干净新二进制重跑：六个攻击用例均为旧 exit=0／新 exit=2，新端 before=after 且不创建锁；dot 控制两端均拒绝，distinct 控制产物旧新字节相等。原始报告 SHA-256 为 `ab87ebe30c21e84662c490466d2306f1be87cb593b3b582518157e5ed53a86ee`。
- 独立 `verify-path-python.py` 使用 realpath／samefile／stat 并重新读取每个 after-state，先通过五项路径已知答案和五类假报告自证，再判八组真实结果。综合证据为 `evidence/path-consistency-2026-11-21.json`，SHA-256 为 `82461aac0486df8ee1add33f33147a5a3f09e70fbd1762af9e260b8055e200a5`。
- 首轮 dangling symlink 单元测试 FAIL（41 过、1 失败）暴露出不存在回退未跟随链接；修复为逐层重定向并限制深度后完整重跑。独立判读器随后因误要求 hardlink 诊断包含 `--state` 而 FAIL；只修正判读器标签，复判同一原始报告，再用干净二进制生成最终报告。
- 本轮只证明协作 CLI 的预检与锁汇聚。验证后恶意改名、跨进程硬链接通用锁、非协作写者、跨主机锁、CAS、WAL／fsync、整份快照回滚、发布者认证、分布式 exactly-once、外部 QF-OS／QIOS 与 ZK 证明仍未获得。

## 2026-11-17 public-only egress 与 DNS rebinding 闭环（历史证据）

- 实现提交为 `32b450b01da77dab77667d930888cb201a913699`（`feat(bridge): pin validated public egress destinations`），基线为 `03cf7d8b7ee71e97fa35f25c6ab9af3ec7a3af26`。从实现提交的 Git 归档在无 `.git`、空 target 环境完整重建，99 个 Rust 测试通过：bridge 单元 37、bridge 集成 48、kernel 11、userspace 3，失败为 0；rustfmt、Clippy、凭据扫描、六类独立判读、固定夹具、执行重放、认知示例和 CLI 烟测全部通过。
- 干净 tar 归档 SHA-256 为 `84213d0f89ecba27c3f120c2afe82f2132dfaff1e4b79760bcbcaa2059597515`，干净 debug 新二进制 SHA-256 为 `4ce77eb6ce94937c39a6fa2f5b99e4297a5a0092ed777b09e0c00453bd3898af`。综合证据为 `evidence/egress-consistency-2026-11-17.json`，SHA-256 为 `39f0ed02005e8416e74e48c2d2b2e28343a57f942f7b394890ef04ebb3186f66`，11 项 artifact 的路径、字节数与摘要已复算。
- HTTP(S) 默认 public-only。IP 字面量直接分类；域名只进行一次策略解析，空答案、超过 32 个答案或任一非公开成员使整组失败。实际 agent 只拨验证后的固定 `SocketAddr`，保留原 Host／TLS server name，环境代理与重定向关闭；解析、连接、读、写共享剩余预算。
- loopback、私网、link-local、shared／CGNAT、文档、benchmarking、reserved、multicast、IPv4-mapped、NAT64、Teredo／IETF、6to4、ULA 与非全局 IPv6 等 48 条预注册已知答案由 Rust 和独立 Python 一致复核。独立判读还拒绝错误状态、伪造 verified 汇总、实际发生连接和额外记录四类假报告。
- 旧新真实进程差分使用上述干净新二进制重跑：旧端访问 loopback 后为 `verified／exit 0／target 1 hit`；新默认端为 `blocked_egress／exit 2／target 0 hit`。显式本地放权时目标 1 hit、恶意代理 0 hit、结果 verified；Registry 注入 `allow_non_public_egress` 则 exit 2、零命中且无报告。原始结果见 `evidence/egress-differential-2026-11-17.json`，SHA-256 为 `9c03a0a48a56ef9607a21ea82a8f95cca030998393a034e37d8fc7528c740490`。
- 首轮 `2001:2::1` 分类顺序 FAIL、Python 对 `::ffff:127.0.0.1` 的判定顺序 FAIL、差分测试器 bytes 编码 FAIL，以及一次外层 shell 状态采集错误均公开保留；修正后从整组重跑，没有把失败当通过。
- 当前结论只覆盖该 HTTP client 的应用层目的地址门禁。它不是 network namespace、外层 egress proxy、hostile OS 防护或通用 SSRF 证明；DNS 调用方等待有界不等于底层系统解析被强制取消，阻塞 worker 线程也未获得资源隔离。外部 QF-OS／QIOS、通用 Skill 沙箱、分布式 exactly-once、签名、独立 witness、WAL／fsync 与整份快照回滚等旧债继续保留。

## 2026-11-16—17 `qfos-exec-v1` 受控执行与恢复（历史证据）

- 实现提交为 `098dab63c3d449bc21a43f79d138b156624b7b15`（`feat(bridge): add bounded wave execution and recovery`）。从该提交的 Git 归档在无 `.git`、空 target 环境完整重建，统一门禁通过 92 个 Rust 测试：bridge 单元 32、bridge 集成 46、kernel 11、userspace 3，失败为 0；rustfmt、Clippy、凭据扫描、五类独立判读、固定夹具重建／字节对拍、执行重放、认知示例和 CLI 烟测均通过。
- 干净归档 SHA-256 为 `c645bedeb4496703417e1d47de689884d6d2089cb8e545d279ea5a9fb871bd89`，干净 debug 二进制 SHA-256 为 `a16bc5e9ea360e078def92d87da9606468771f98af027caa2546f6dedf3ceb6e`。综合证据为 `evidence/execution-consistency-2026-11-17.json`，SHA-256 为 `6703407ff64ee27226cc197c32baf3df8d3aee3107776db866368931090401b9`，其 11 项 artifact 的路径、字节数与摘要已复算。差分新端 `07444fd6…e24` 仍是提交前工作树 debug 二进制，不与上述干净二进制混用。
- 执行面只开放 `engine.sum` 与 `engine.sha256`。前者最多 1024 个 `i64` 并逐项检查溢出，后者最多 1048576 个 UTF-8 字节；无 shell、无网络、无动态库、无外部进程。未知动作、非法载荷、输入超限、算术溢出和执行前过期形成五类显式死信。
- 固定夹具含 7 项指令，初次执行为 2 个成功回执＋5 个死信、7 consumed、0 pending；`sum` 真实输出为 `{"count":3,"sum":42}`，Unicode SHA-256 输出可独立复算。计划哈希为 `f64a8bcc87aa7c2a33f59bfc084bc34ab6626c51d263aac86c1190b35e54254a`，执行报告哈希为 `4cefca364f55ef97a41aeb580ab01b6c16c7a754a02acc78b23e14fc6da5a78c`。
- LedgerSnapshot v4 将 pending 删除、consumed tombstone、成功回执和死信保存在同一原子快照。库内执行先在克隆账本暂存，容量失败不留下成功前缀；执行模式先持久化原计划，再保存执行后状态，最后写报告。报告输出失败后，恢复原计划只得到 2＋5 skipped；再次重放的账本与报告字节不变。磁盘原子可见性仍只有临时文件＋rename，不声称 fsync 掉电持久性。
- 独立 `verify-execution-python.py` 从内建语义重算真实输出、失败类别和全部摘要，并勾稽计划、报告与最终状态。五项自证通过，其中重新计算内部及报告哈希后的假 sum、假失败类别和假报告结果仍被拒绝。旧新真实进程差分九项检查全部通过：旧端提交 `320b226ca7b605f41744f50e970b2371077bebdb` 无执行参数且 7 项保持 pending，新端产生真实结果并在重启后全部 skipped；原始结果见 `evidence/execution-differential-2026-11-16.json`。
- 当前结论仅覆盖仓内 `qfos-exec-v1`。它不是已验证的外部 QF-OS 正典执行协议，不声称 QIOS 兼容、通用 Skill 沙箱、租约、跨进程分布式 exactly-once、发布者认证、结果签名或形式化执行证明。

## 2026-11-14 全轮询与 JSON 资源预算（历史证据）

- 实现提交为 `33ff4a63d9dfd7e20c6d34b79296cd400d5e07f4`（`feat(bridge): enforce poll and JSON resource budgets`）。85 个 Rust 测试通过：bridge 单元 29、bridge 集成 42、kernel 11、userspace 3，失败为 0；Clippy 零警告。
- 从该提交的 Git 归档在无 `.git`、空 target 环境完整重建，统一门禁全部通过。归档 SHA-256 为 `f77faa8aca8395bcec297397165dde315ee96b023092f411e2b71df216ac552b`，干净二进制 SHA-256 为 `95a75c596363242c674e8b4ab1a17a6ac40a053d3d28d9b5f348b1c25b48db77`。
- CLI 默认全轮询预算为 60000ms，`--poll-timeout-ms` 只能调低。活动 HTTP 请求使用单请求 15 秒与剩余预算的较小值；会话间和状态保存前复核 deadline。旧库兼容入口仍只有逐请求超时，不可信 Registry 必须调用 `poll_registry_detailed_with_deadline`。
- Registry、Outbox、LedgerSnapshot 共用 64 层与 16384 个 JSON 值节点硬顶。根深度为 1，容器与标量各计一个节点，对象键不另计，所有分支共享计数；开放 `mailbox` 和 `payload` 同样受限。
- 五组预注册差分全部通过：TIME-01 旧端 354.46ms 两跳均 verified，新端 44.06ms 非零退出、第二跳零请求且无报告；TIME-02 四种非法预算参数均在 I/O 前拒绝；JSON-01／02 旧端接受深层／超节点 mailbox，新端显式拒绝；JSON-03 旧端接受深层 Snapshot，新端轮询前拒绝且状态字节不变。
- 差分证据 SHA-256 为 `99981b538d53764dd005691c73f8c7562f911158e803e9d7083d44f2f8e77e50`。首轮手工 genesis 夹具缺字段导致 FAIL，已作为 `harness_corrections` 保留，修正后整组重跑，没有把 FAIL 计入通过。
- 独立 `verify-json-budget-python.py` 以显式栈迭代复算深度／节点，并对精确边界、跨分支计数和转义重复键执行五个已知答案自证。综合证据为 `evidence/resource-budget-consistency-2026-11-14.json`，SHA-256 为 `14b50a84cbacc1291bcb7ccc2ed18df4c79d51c8ff368693f4ec21a8c1b214f9`，七项 artifact 已复算。
- 干净二进制于 2026-11-14T15:17:42Z 在 60 秒总预算下重采七端点，仍为 `total=7, verified=1, failed=6`；原始报告为 `evidence/resource-budget-poll-2026-11-14.json`。这不证明远端 Git 同步、发布者身份或联盟状态。

## 上一轮 QF-OS 融合实测（历史证据）

- 实现提交为 `88a92e3778a3664f62835aa1746f21b9b831433c`（`feat(bridge): add bounded QF-OS wave planning`）。78 个 Rust 单元／集成测试通过：bridge 单元 27、bridge 集成 37、kernel 11、userspace 3，失败为 0。
- 从该提交的 Git 归档解到无 `.git` 的干净目录，并使用空 `CARGO_TARGET_DIR` 完整执行 `scripts/build-all.sh`。格式检查、Clippy 零警告、78 项测试、凭据扫描、Outbox／Policy／Wave Python 独立判读、波次临时重建与 fixture 字节对拍、认知示例和 CLI 烟测均通过。
- 干净归档 SHA-256 为 `f25eefdcbd83f3bdbf8e9dcb592673d33ed39f310325dc0e45a92d8d53ea3602`，干净重建二进制 SHA-256 为 `e6cbf30c7cc47467696894f5ab1177f603e30ba3267e698b02be92b73ac4f2d6`；五组旧新攻击使用同一干净二进制重跑并全部通过。
- 认知示例精确输出为 `skill_output={"sum":42}; edge=1; matches=[1]`。CLI 烟测为 `total=3, verified=1, failed=2`，两个失败是故意设置的非法 JSON 和缺失文件；v3 烟测状态策略摘要为 `d7bb090c4022b10a3f46ca236315cd96a77091ca0edeac038fac4016245d6a19`。
- 综合机器证据为 `evidence/attack-consistency-2026-11-14.json`，SHA-256 为 `1cd3f9341c83ef647971be2c7c7077466a0bcfac692bb58b3a7de5d92275b108`。其 10 项 artifact 的路径、字节数与 SHA-256 已独立复算，且差分新端哈希与干净重建二进制一致。

## 2026-11-14 QF-OS 计划面新增安全性质（历史证据）

1. **有界轮询扇出**：Registry 除 2 MiB 字节上限外，最多 64 个 session；第 65 个会话导致任何 socket I/O 前非零失败。
2. **有界持久队列**：pending、tombstone、单 Outbox 已验证指令分别硬限 4096、16384、1024；CLI 参数只能调低，缺值或试图调高均失败。
3. **容量事务**：每份 Outbox 在克隆账本中暂存入库；任一容量超限会丢弃整个批次，不提交前面的成功前缀。恢复超基数 snapshot 和写出超 16 MiB 也失败关闭。
4. **消费不丢任务**：tombstone 满时，消费在删除 pending 前失败；原状态字节保持不变，待办仍可后续处理。
5. **协作写者排他锁**：`--state` 在加载前取得稳定 `<state>.lock` sidecar 的 OS 排他锁并持有到输出结束；竞争进程非零退出。它只覆盖使用相同词法路径的协作 CLI，不是分布式锁。
6. **QF-OS 波次接口**：`qfos-wave-plan/v1` 从已验证账本生成来源轮转、全局／来源双配额、显式 deferred 的确定性计划，绑定 network、policy、完整 snapshot、Job 和来源计数。
7. **计划能力边界**：计划模式固定为 `plan-only-no-execution`；生成计划不改账本、不消费指令、不执行 action、不调用 Skill。`plan_hash` 只是完整性摘要，不是执行证明或签名。
8. **独立波次判读**：Python 从 Registry 与原始 snapshot 重建过滤、轮转、配额、计数和双摘要；篡改 Job 或账本绑定均拒绝。

既有严格 JSON、传输授权、禁重定向、正典 URL、网络＋策略绑定、完整验链后入库和历史检查点继续有效。无签名链、策略摘要、账本摘要和计划摘要均不认证发布者。

## 旧新 CLI 差分

旧端为前一提交 `143668c20a79d2bcde5d555bee15be6cf8da2c91` 的 Git 归档构建；新端为上述实现提交的干净归档构建。判据在实现前登记于 `evidence/qfos-fusion-preregister-2026-11-14.json`，原始结果见 `evidence/differential-2026-11-14.json`，其 SHA-256 为 `61d66e79c01b9433e9ac4ef3607a26ab699fa2ebfe50a23281e1a5e1b203d982`。

| 攻击 | 旧端实测 | 新端实测 |
|---|---|---|
| SAT-01：5 个 pending，新端 cap=4 | 返回 0，pending=5 | 返回 2，整批拒绝，state／report 均不创建 |
| SAT-02：连续消费制造 tombstone | 五次均返回 0，consumed=5、pending=0 | cap=2 后第三次返回 2，状态字节不变，consumed=2、pending=3 |
| SAT-03：以低 cap 恢复 5 项 snapshot | 返回 0 并接受 | 轮询前返回 2，状态不变且不生成报告 |
| SAT-04：65 个 HTTP session | 实际传输命中 65 次，report.total=65 | 返回 2，传输命中 0，state／report 不创建 |
| LCK-01：双进程消费不同 ID | 两端均返回 0，但最后只剩 1 个 tombstone，另一消费被丢失 | 锁竞争者返回 2 且零竞争网络命中；显式重试后 consumed=2，两项均保留 |

`PASS` 只表示五项预注册旧新判据成立，不证明非协作写者、跨主机锁、分布式 CAS 或全系统安全。

## 2026-11-14 QF-OS 计划面实测与 QIOS 边界（历史证据）

静态向量包含两个来源、五条未过期指令、一条过期指令、一个通配目标和非 ASCII 载荷。以 `max_jobs=3`、`max_per_source=2` 生成计划：

```text
admitted = [a1, b1, a2]
a3 → deferred_source_quota
b2 → deferred_wave_quota
plan_hash = fefb2704c277115cf4f88e2215cfb7a10cb508694a43527c300700ed47003302
```

`evidence/wave-oracle-2026-11-14.json` 记录独立重建及两个篡改负例。构建门禁会从原始 fixture 重新生成 state／plan，并与提交字节 `cmp` 相等。

该历史阶段只实现 QF-OS 的**计划面接口**；上述 `fefb2704…3302` 是当时 v3 状态夹具的计划哈希，不回写为当前 v4 静态计划哈希。2026-11-16 已新增仓内 `qfos-exec-v1` 的两种内建动作、本地原子回执／死信与重启跳过，但引擎租约、失败重试策略、结果签名、通用 Skill 沙箱和外部正典适配仍未接入。QIOS 在仓内、已读在役定义和精确公开检索中均未解析为本项目正典实体；搜索结果中的同名医疗或其他领域术语不是适配依据。因此当前没有 QIOS adapter、兼容性或互操作完成声称。

## 独立判读与跨语言勾稽

- `verify-outbox-python.py`：无浮点 V1 链重算、指令来源检查、已知答案和篡改自证；不是 RFC 8785 JCS。
- `verify-policy-python.py`：Registry 安全投影、策略摘要、三项自证和 live snapshot 对拍；fixture 摘要仍为 `d5805bd450f0778f996fd6094d3a1723114da35be1adee5ca8bd0f361a3c7a21`。
- `verify-egress-python.py`：独立 `ipaddress`／CIDR 地址分类、48 条已知答案与 blocked 报告复核；四类假报告自证通过，不证明外层网络隔离。
- `verify-path-python.py`：独立 realpath／samefile／stat、八组旧新结果与文件系统 after-state 复核；五项路径已知答案和五类假报告自证通过，不证明预检后路径名不可被敌对修改。
- `verify-atomic-write-python.py`：从真实 PID 独立重建临时名，复核五组旧新结果及当前文件系统的类型、链接目标、身份和 SHA-256；四项已知答案和五类假报告自证通过，不证明临时项创建后至 rename 前无竞态。
- `verify-lock-symlink-python.py`：独立复核真实双进程 liveness、FIFO 字节、v4 状态迁移、链接目标、inode 和 SHA-256，并检查 Unix `O_NOFOLLOW` 的实际 open 顺序；五项已知答案和六类假报告自证通过，不覆盖取锁后的路径名替换或非 Unix 竞态。
- `verify-wave-python.py`：从原始 snapshot 重建完整波次计划；两个篡改自证通过，范围为无浮点 qfos-wave-v1 子集，不是签名、执行或 QIOS 证明。当前 v4 静态计划哈希为 `5b27a80652ea74fc1b11e07033119ea49708018244325e5dae56f0f6bb88ca34`。
- `verify-execution-python.py`：独立推导执行输出与五类失败、重算全部摘要并勾稽计划／报告／最终状态；五项自证含 rehashed 假语义，固定执行夹具为 2 回执＋5 死信。
- `verify-ticket-utxo-python.py`：独立重建票／交易 ID、账本 digest、血缘、根序列与预算、唯一作业链、spent 集合、Execute↔结果绑定和根撤销时间顺序；亲自验收每个伪造快照。3 个已知答案、1 个合成有效、4 个合成拒绝及伪造真实报告拒绝先于真实 9 组／48 进程报告验收。

## 公网交叉验证

使用干净归档二进制，于 2026-11-14T08:14:05Z 轮询七端点：`asfa-ai=verified`；cfts／cisvr／qgl／ucif2／usrm 为 HTTP 404；vinf 因未知字段 `chain_len` 为 `invalid_schema`。原始报告见 `evidence/poll-2026-11-14.json`，SHA-256 为 `e303f1b73fcc2c10e0749c3c4d0c2275c1cb4714cb5c07cff3016dd387da2a30`。

公网 jsDelivr 镜像与仓内 Outbox 字节相等，SHA-256 均为 `c0df0e35f63b20049ab9da97fe80509ef918ae0e3b1ad79d5e5f9ac7e36f56b4`；两份均通过 Python 判读与篡改自证。该相等不表示远端 Git main 等于本地实现提交，也不认证发布者。详见 `evidence/public-python-oracle-2026-11-14.json`。

## 联邦、凭证与推送边界

最后已核验正典状态仍为历史记录 `asfa-ai = conditional`（2026-11-09）。本轮没有 cisvr ACK、正典升 active 或 KEY-SYNC-01 relay 完成回执；写入 Outbox 不等于真实投递或对方 ACK。

本地 remote 为 `https://github.com/chepin-ai/test.git`，不含明文凭证。此前泄露的 PAT 仍应撤销／轮换，当前没有 GitHub 侧撤销证据。上一轮推送以 TLS 错误和非交互认证缺失失败，最终远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`，当时候选为 `ahead_by=13, behind_by=0`；原始记录见 `evidence/execution-publication-2026-11-17.json`。

本轮 egress 证据候选为 `713a3608bee51b9ac44aa1728e06fdecc9b5a71c`。2026-11-17 无凭证 `ls-remote` 第一次即成功，远端仍为同一 `c573dc4…`；候选相对远端为 `ahead_by=15, behind_by=0`。当前无可用 PAT／CMD，未发起认证推送，结论为 `NOT_PUSHED`、`remote≠local`，没有新外部 CI；未恢复或输出任何历史凭证。证据提交仅 amend 发布记录与对应文档，分叉计数不变。原始记录见 `evidence/egress-publication-2026-11-17.json`。

本轮输出路径证据候选为 `759daf69ea1981753f17f23511efedce88fe1888`。2026-11-21T00:17:45+08:00 无凭证 `ls-remote` 成功，远端 `main` 仍为 `c573dc496dc3caeab1f0f143373c80859ccd93d4`；候选相对远端为 `ahead_by=17, behind_by=0`。当时无可用 PAT／CMD，未发起认证推送，结论为 `NOT_PUSHED`、`remote≠local`。该记录保留为历史时点快照，原始记录见 `evidence/path-publication-2026-11-21.json`。

后续真实推送已改变当前事实，但不回改上述快照：第一枚现场凭证认证失败、push exit 128 且无 ref 更新；第二枚现场凭证仅执行一次 push，exit 0，将唯一允许的远端 `main` 从 `c573dc496dc3caeab1f0f143373c80859ccd93d4` 更新到 `2a40df076c0d4f63a1f5dd25f368f2916a8d0d50`。首次读后遇 HTTP/2 framing error，HTTP/1.1 重读后确认该 pushed commit 当时 remote=local、ahead／behind=0。公共 Actions workflow-runs 列表 API 实测 run `44784042393`（`build-test-smoke`、event=`push`）的 `head_sha=2a40df0…`、status=`completed`、conclusion=`success`；单 run／jobs API 返回 403，不作 job 级声称。完整回执见 `evidence/path-push-2026-11-21.json`。该推送与 CI 不覆盖原子写实现 `46cf446…` 或后续证据提交；已消费凭证不复用，本轮仍无 cisvr ACK、KEY-SYNC-01 relay、正典 active 或旧 PAT 撤销证据。

本轮任务票证据候选为 `5469b52424316521de90c8bd3b730bfbc39590ae`。2026-11-22T00:02:21+08:00 两次无凭证 `ls-remote` 均遇 TLS 终止；改用 GitHub 公共 commits API 读到唯一允许远端 `main=2a40df076c0d4f63a1f5dd25f368f2916a8d0d50`，候选相对远端为 `ahead_by=6, behind_by=0`。未复用已消费凭证或发起认证推送，结论为 `NOT_PUSHED`、`remote≠local`，没有本轮外部 CI。发布记录及索引 amend 后分叉计数不变，最终 HEAD 以 Git 实测为准。原始记录见 `evidence/ticket-utxo-publication-2026-11-21.json`。

## 明确未实现与后续债

1. 本 HTTP client 之外的出口流量、network namespace、外层 egress proxy、hostile OS 与通用 SSRF 防护；
2. 底层 DNS 强制取消、阻塞 resolver 线程回收与资源隔离；应用层单次解析、全答案验证和连接固定已实现；
3. 进程级内存、CPU、文件描述符硬隔离与 CLI 轮询阶段外的整体执行预算；全轮询 deadline、解析等待与逐请求剩余时间、JSON 深度／节点预算已实现；
4. 输出预检后的恶意路径改名、取得锁后的常规 lock pathname 替换、账本临时项创建后至 rename 前的恶意替换、非 Unix check/open 竞态、跨进程硬链接通用锁、非协作写者、跨主机锁语义、CAS、WAL 和原子 check-and-persist；CLI 同路径／symlink／既有硬链接判重、最终状态路径 symlink 锁汇聚、预置 lock symlink 拒绝＋Unix `O_NOFOLLOW`、常规／hardlink sidecar 跨 rename 排他与临时项 `create_new` 独占分配已实现；
5. 整份快照回滚、分裂视图、签名 checkpoint、独立 witness／quorum；
6. 发布者与指令授权、可信时间；
7. 完整 JCS V2、Merkle consistency proof、后量子 witness；
8. 仓内 `qfos-exec-v1` 之外的通用动作与 Skill 沙箱、引擎租约、失败重试策略、结果签名／形式化证明、跨进程分布式 exactly-once、外部 QF-OS 正典与 QIOS 定义／适配器；任务票当前也无拆波执行、自主开单、规则赛马、动态信用、通用 eUTXO 脚本、Sui 共享对象、Gas 市场、事件总线或外部结算；
9. 联盟 active、cisvr ACK、KEY-SYNC-01、旧 PAT 撤销，以及原子写／状态锁／任务票实现与后续证据提交的远端同步和外部 CI 回执；`2a40df0…` 的推送与 run `44784042393` 不回写成这些新提交的发布证据；
10. Boot／裸机内核、WASM、TEE、ZK-SNARK／STARK、HoTT-ZK、涌现类型系统、量子调度、神经网络推理、Holo-Lang 与完整形式化安全证明。

## 形式化内容边界

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统或 QF-OS 波次执行的安全证明。历史 `Admitted` 占位文件已删除。
