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
  chain                   负载哈希、逐块链接、终端指针验证
  poller                  文件与 HTTP(S) 获取、显式负结果
  ledger                  指令去重、过期拒绝、单次消费
  main                    一次性 CLI；不包含后台守护进程
```

## 数据流

```text
sessions.json
    │ 逐会话读取（BTreeMap 确定顺序）
    ▼
文件 / HTTP(S) ──失败──► HttpStatus / Transport 负记录
    │
    ▼
JSON 解析 ──失败───────► InvalidJson 负记录
    │
    ▼
Outbox schema + session 对拍 ──失败──► InvalidSchema 负记录
    │
    ▼
trust mode + 全链重算 ──失败───────► UnsupportedTrust / InvalidTrust
    │
    ▼
Verified 报告 + 区块内指令 → DirectiveLedger
```

顶层 `directives` 是未认证兼容元数据，不进入可信指令计数。系统调用即证明、涌现即类型、ZK-ML 等先前概念不在当前实现路径中。
