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
  strict_json             递归重复键拒绝、未知协议字段拒绝、有界文件读取
  chain                   负载哈希、逐块链接、终端指针验证
  poller                  显式 file／HTTP 授权、禁重定向、正典 URL 与完整链验证
  ingest                  全链复验＋历史检查点对拍＋暂存账本容量事务
  ledger                  网络＋安全策略绑定、指令去重、有界 tombstone、链头检查点与原子快照
  state_lock              稳定 sidecar 上的协作 CLI 排他锁
  wave                    QF-OS 来源轮转、双配额、deferred 计数与计划／账本摘要
  main                    一次性 CLI：轮询、入库、显式消费、波次计划、状态保存；不是守护进程
```

## 数据流

```text
sessions.json
    │ 逐会话读取（BTreeMap 确定顺序）
    ▼
文件 / 默认 HTTPS（HTTP 需显式授权；禁重定向） ──失败──► HttpStatus / Transport
    │
    ▼
严格 JSON（嵌套键唯一、未知协议字段拒绝） ──失败──► InvalidJson / InvalidSchema
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
    ├─可选 plan_wave（来源轮转＋双配额；只读、不执行）
    ▼
save_atomic(v3 state) → ingestion 报告／qfos-wave-plan/v1
<state>.lock 在加载前取得，覆盖整个 CLI 状态与输出临界区
```

顶层 `directives` 是未认证兼容元数据，不进入可信指令计数。CLI 是进程级一次性运行；跨重启防重放与历史一致性依赖调用方提供 `--state`，没有自动后台轮询或 WAL。状态恢复强制网络身份、完整安全策略摘要和本地资源上限对拍；协作 CLI 由 sidecar 排他锁隔离，但路径别名、非协作写者和分布式 CAS 未覆盖。本地检查点也不能抵御整份快照被旧文件替换。独立 Python 判读器提供无浮点 V1 链、Registry 策略及 QF-OS 波次重建，不是 JCS、签名、外部 witness 或引擎执行证明。重定向禁止不等于完整 SSRF 防护，DNS／私网地址、全轮询总 deadline 与出口策略仍须外层控制。QIOS 没有已核验适配器；系统调用即证明、涌现即类型、ZK-ML 等先前概念不在当前实现路径中。
