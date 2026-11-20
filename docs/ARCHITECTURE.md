# 实际架构

## Crate 分层

```text
asfa-kernel
  cognitive::hypergraph   确定性 n 元关系存储与检索
  cognitive::hippocampus  键值记忆与最近向量导航
  cognitive::operad       带元数检查的计算组合

asfa-userspace
  Agent                   身份、位置、Skill 所有权
  SkillRegistry           JSON 输入/输出的命名处理器

asfa-bridge-poller
  model                   注册表、Outbox、指令、报告 schema
  strict_json             重复键拒绝、64 层／16384 节点共享预算、未知字段拒绝、有界读取
  chain                   负载哈希、逐块链接、终端指针验证
  egress                  public-only 地址分类、完整答案 fail-closed、有界单次解析与固定 SocketAddr
  poller                  显式传输授权、禁重定向／环境代理、全轮询 deadline、实际连接固定与完整链验证
  ingest                  全链复验＋历史检查点对拍＋暂存账本容量事务
  ledger                  网络＋安全策略绑定、指令去重、有界 tombstone、链头检查点、v4 回执／死信原子快照、create_new 独占临时分配
  output_paths            输出目标解析、dangling symlink 跟随、同路径与既有文件身份判重
  state_lock              解析后状态目标对应的稳定 sidecar 协作 CLI 排他锁
  wave                    QF-OS 来源轮转、双配额、deferred 计数与计划／账本摘要
  execution               qfos-exec-v1 纯内置执行、真实输出、五类死信、暂存提交与恢复幂等
  main                    一次性 CLI：轮询、入库、显式消费、波次计划、受控执行、状态保存；不是守护进程
```

## 数据流

```text
sessions.json
    │ 逐会话读取（BTreeMap 确定顺序；默认 60 秒全轮询 deadline）
    ▼
文件 / 默认 HTTPS（HTTP 需显式授权；禁重定向／环境代理；逐请求剩余时间） ──失败──► HttpStatus / Transport
    │ HTTP(S)：IP 直接分类；域名解析一次并验证全部答案；连接只拨固定地址
    ├─非公开目的／空或超量答案──► BlockedEgress / Transport（零 HTTP 拨号）
    ▼
严格 JSON（键唯一、64 层／16384 节点、未知协议字段拒绝） ──失败──► InvalidJson / InvalidSchema
    │
    ▼
Outbox schema + session 对拍 ──失败──► InvalidSchema 负记录
    │
    ▼
canonical_url + trust mode + 全链重算 ──失败──► UnsupportedTrust / InvalidTrust
    │
    ▼
Verified 报告 + 已验证 Outbox
    │
    ▼
ingest_outbox 再次完整验证 ──任一坏块──► 整份 Outbox 零入库
    │
    ├─本地 (height,latest) 对拍──回滚／分叉──► 指令与检查点零变更
    ▼
DirectiveLedger（绑定 network_name＋policy_hash＋容量上限）
    ├─可选显式消费（tombstone 满则零变更）
    ├─可选 plan_wave（来源轮转＋双配额；计划生成只读）
    ├─执行模式先持久化原计划，再于克隆账本 execute_wave
    │    ├─engine.sum／engine.sha256 → 真实输出＋回执
    │    ├─未知／非法／超限／溢出／过期 → 显式死信
    │    └─已有结果 → skipped；consumed 无结果 → fail-closed
    ▼
save_atomic(v4 state；create_new 独占临时项，≤128 冲突重试) → ingestion／qfos-wave-plan/v1／qfos-wave-execution/v1
所有输出先经 output_paths 判重，再在加载前取得 <resolved-state>.lock，覆盖整个 CLI 状态与输出临界区
```

顶层 `directives` 是未认证兼容元数据，不进入可信指令计数。CLI 是进程级一次性运行；跨重启防重放与历史一致性依赖调用方提供 `--state`，没有自动后台轮询或 WAL。状态恢复强制网络身份、完整安全策略摘要和本地资源上限对拍；协作 CLI 由解析目标后的 sidecar 排他锁隔离；所有声明输出另做同路径与既有文件身份预检；账本临时项由 `create_new` 独占分配并有界处理冲突，但验证后恶意改名、临时项创建后至 rename 前的恶意替换、跨进程硬链接通用锁、非协作写者和分布式 CAS 未覆盖。本地检查点也不能抵御整份快照被旧文件替换。独立 Python 判读器提供无浮点 V1 链、Registry 策略、迭代 JSON 资源计数、egress 地址分类／假报告反证、输出路径 realpath／samefile／stat 复核、原子写文件类型／链接目标／身份／SHA-256 重读、QF-OS 波次重建及 `qfos-exec-v1` 内置输出／失败类别／持久结果复核，不是 JCS、签名、外部 witness 或通用引擎证明。HTTP(S) 已有应用层 public-only 分类、全答案验证、单次解析与实际连接固定，但仍需外层 egress 隔离应对非协作进程或 hostile OS；DNS 调用方等待有界不等于底层解析被强制取消。`qfos-exec-v1` 仅是本仓两个确定性内置函数的受控执行契约，不是外部 QF-OS 正典；QIOS 没有已核验适配器，分布式 exactly-once、系统调用即证明、涌现即类型、ZK-ML 等先前概念不在当前实现路径中。
