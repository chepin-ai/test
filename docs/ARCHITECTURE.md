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
  strict_json             递归重复键拒绝；不是完整 JCS
  chain                   负载哈希、逐块链接、终端指针验证
  poller                  文件与 HTTP(S) 获取、完整验证、显式负结果
  ingest                  全链复验＋历史检查点对拍后才应用指令
  ledger                  网络绑定、指令去重、tombstone、链头检查点与原子快照
  main                    一次性 CLI：轮询、入库、显式消费、状态保存；不是守护进程
```

## 数据流

```text
sessions.json
    │ 逐会话读取（BTreeMap 确定顺序）
    ▼
文件 / HTTP(S) ──失败──► HttpStatus / Transport 负记录
    │
    ▼
严格 JSON（所有嵌套对象键唯一） ──失败──► InvalidJson 负记录
    │
    ▼
Outbox schema + session 对拍 ──失败──► InvalidSchema 负记录
    │
    ▼
trust mode + 全链重算 ──失败───────► UnsupportedTrust / InvalidTrust
    │
    ▼
Verified 报告 + 已验证 Outbox
    │
    ▼
ingest_outbox 再次完整验证 ──任一坏块──► 整份 Outbox 零入库
    │
    ├─本地 (height,latest) 对拍──回滚／分叉──► 指令与检查点零变更
    ▼
DirectiveLedger（绑定 network_name） → 可选显式消费 → save_atomic(v2 state) → ingestion 报告
```

顶层 `directives` 是未认证兼容元数据，不进入可信指令计数。CLI 是进程级一次性运行；跨重启防重放与历史一致性依赖调用方提供 `--state`，没有自动后台轮询或 WAL。状态恢复强制网络身份对拍，但只支持单写者；原子保存不能防止并发丢失更新，本地检查点也不能抵御整份快照被旧文件替换。独立 Python 判读器提供无浮点 V1 子集的跨语言重算，不是 JCS 或外部 witness。系统调用即证明、涌现即类型、ZK-ML 等先前概念不在当前实现路径中。
