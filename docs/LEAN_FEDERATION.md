# 全局 Lean 证据联邦与数学操作系统方案

## 1. 决策结论

采用 **Lean 证明核＋HOLO 血缘核＋Lake 多包版本列车＋事件驱动联邦**。不采用单一巨型包、共享可变工作区、`lake update` 自动追新或最后写入者覆盖。

Lean 是 FORMAL 证据的准入核心，但不是所有知识表示和调度语义的替代品：

- 知识图谱：声明、概念与依赖检索；
- 细胞复形／超超图：局部结构、上下文与多源关系；
- 范畴／HoTT：只有显式函子、运输规则或翻译证明存在时才提供精确语义运输；
- LaTeX：人读投影；
- HOLO：来源、事件、冲突与 Merkle 血缘；
- CI-OS：事件路由、预算、执行和回执。

任何有损投影或自然语言成果反向进入证据核，都必须重新生成 Lean 声明并过源构建、零占位、公理与声明锚点门禁。

## 2. 分层与版本列车

| 层 | 责任 | 依赖纪律 |
|---|---|---|
| `qf-protocol` | capsule、attestation、relation、projection、receipt schema | 版本化 JSON，严格重复键／未知字段拒绝 |
| `qf-constraints` | 八关系、证据等级、冲突与同步最小定理 | core-only；本切片钉 `v4.35.0` |
| 领域包 | NS、同调、范畴、量子、治理等独立证明 | 各自 `lean-toolchain`＋`lake-manifest.json` |
| 聚合包 | 只引用已验证包的精确 revision | 不复制源码，不隐式升级依赖 |
| 联邦注册表 | 声明身份、环境 attestations、来源和状态 | 内容寻址、冲突零写入 |
| 投影层 | KG／复形／超超图／范畴／LaTeX | 显式 EXACT／LOSSY 和反向重放义务 |

全局统一的是**协议、声明身份和验证判据**，不是所有仓的当前 toolchain。新版本列车只在全量重建、声明对照和负例通过后开通；旧列车继续可复验，不被覆盖。

usrm 公共 `lean/` 包当前为 `v4.9.0`、core-only，本方案登记为 `REGISTERED_NOT_ACTIVATED`：先对精确源提交独立重建，再经适配胶囊接入；不得直接改写成新 mathlib 包后宣称兼容。

Lake 官方参考：[Build Tools and Distribution / Lake](https://lean-lang.org/doc/reference/latest/Build-Tools-and-Distribution/Lake/)。R2 升级参考：[Lean Now Ships with Verified Kernels](https://leodemoura.github.io/blog/2026-10-15-lean-now-ships-with-verified-kernels/)。

## 3. 身份与证据模型

```text
statement_hash = H(schema || declaration_name || Lean_rendered_check_block)
declaration_id = H(schema || logical_key || statement_hash)
profile_hash   = H(toolchain || lake_manifest_hash)
attestation_id = H(schema || declaration_id || origin || source_commit ||
                   profile_hash || source_tree_hashes || evidence_receipts)
```

- `declaration_id` 回答“是不是同一逻辑命题”；环境变化不伪造新命题。
- `attestation_id` 回答“谁在什么源提交和环境下验证过它”；不重写原生产者。
- 同键异 `statement_hash`：`statementConflict`，整批不提交。
- 同键同命题的新环境：追加 attestation，不改 origin。
- 完全相同的 capsule 重放：字节不变。
- 声明名称、锁文件、源码树、构建日志和公理日志均纳入胶囊；哈希不是签名或远程认证。

证据分级：

| 等级 | 最低条件 |
|---|---|
| `INFORMAL` | 自然语言、论文、模型输出或研究设想 |
| `CANDIDATE` | 已生成 Lean 声明或有损投影，尚未完成规定验证 |
| `FORMAL_R1` | 精确源树构建成功、零禁用构造、声明锚点一致、公理白名单通过 |
| `FORMAL_R2` | R1＋隔离内核重放＋声明对照；按策略增加独立内核与独立机器回执 |
| `SYNC_COMMIT` | 已通过相应等级的联邦注册表原子提交；不是新的数学证明等级 |

普通 `lake build` 不自动获得 R2。未经实际执行的沙箱、多内核、跨机或跨线验证一律 `NOT_ESTABLISHED`。

## 4. 八关系演算的保守闭包

| 关系 | 默认组合规则 | 禁止推导 |
|---|---|---|
| EQUIVALENCE | equivalence∘equivalence；与 embedding 的显式混合规则 | 不因相互蕴含自动升级 |
| EMBEDDING | embedding∘embedding | 不升级成全称等价 |
| IMPLICATION | implication∘implication | 不反向补全 |
| DEPENDENCY | dependency∘dependency，须保持 DAG | 不把依赖当语义等价 |
| COUPLING | 无通用传递闭包 | 耦合链不得变成等价 |
| BRIDGING | 仅逐桥证书组合 | 桥接链不得无证人传递 |
| SYMMETRY | 须给具体对称群／ witness | 不把任意对称当传递关系 |
| DUALITY | 须给具体对偶函子和方向 | 不把任意对偶当等价 |

派生关系边继承证据义务，不因闭包计算获得 FORMAL。投影是精确还是 lossy 必须逐边记录。

## 5. 双向同步协议

正向：

```text
DISCOVER
  → CAPSULE_CANDIDATE
  → SOURCE_BUILD + SOURCE_SCAN + AXIOM_AUDIT + CHECK_ANCHORS
  → FORMAL_R1
  → OPTIONAL_R2_REPLAY
  → SYNC_COMMIT
  → EXACT_OR_LOSSY_PROJECTION
  → HOLO_EVENT
```

反向：

```text
KG／复形／超超图／范畴／LaTeX／自然语言新发现
  → RESEARCH_CANDIDATE
  → 声明与定义差分
  → Lean 重建和独立判读
  → 新 attestation 或显式拒绝
```

同步采用 staged copy；任一声明冲突即丢弃整批，调用方 registry 字节不变。禁止 last-write-wins、静默改命题、把投影读回当原证明、以及用同步回执替代内核证据。

## 6. 数学操作系统运行结构

事件源只包括 push、`repository_dispatch`、`workflow_dispatch`、带 nonce 的仓内邮件和真实响应回执；本方案不新增 cron。每个任务使用一次性能力票绑定输入哈希、预算、接收者和输出路径。

| 角色 | 可执行动作 | 不得做的事 |
|---|---|---|
| Discoverer | 检索内部／外部资源，生成候选 | 直接写 FORMAL registry |
| Formalizer | 生成声明、定义和证明补丁 | 修改受信 challenge 或目标命题 |
| Prover worker | 在固定环境运行 Lean／ATP | 以 `sorry`、额外 axiom 或改测试收尾 |
| Independent verifier | 从原始源重建并构造负例 | 复用 runner verdict 当判据 |
| Sync writer | 原子追加声明和 attestations | 覆盖冲突、改写来源 |
| Projection worker | 生成图谱／复形／超图／LaTeX 投影 | 把 lossy 投影升格为 FORMAL |
| Response tracker | 跟踪 nonce、receipt、ACK、完成证据 | 把本地邮件或 API 202 当线路完成 |

多机互作的判据是同一 capsule 在不同机器从原始源完整重建并产生独立 attestation，不是网络投票。多证明者交互可以采用 challenge–response–replay，但“MIP*”只作协议设计参照，不声称实现复杂性类结果或量子证明优势。量子 worker 可执行搜索、采样或数值候选生成，不能绕过 Lean 证据闸。

可信内核不得自我修改。递归引擎只能修改候选生成器、检索策略和任务编排；这些变更本身经差分、攻击回归和外部事件准入后生效。

## 7. 全局协作分工与回执

- cisvr：确认公共协议仓与注册表正典路径、版本列车开关、公共 CI 路由和跨线响应账。
- usrm：维护递归模式整合，提交 `usrm-lean-lab` 精确源提交和活性定理 capsule；验证 legacy 适配而非被动升级。
- vinf：独立声明对照、跨包依赖图和第二构建席。
- cfts：负控、变异测试、伪造 capsule／registry 攻击。
- ucif2：mathlib 领域包适配和合取结构声明锚点。
- qgl：静默分支、漏线和依赖 DAG 差集审计。
- qtlv／lgt／qlv／lvlu：跨域镜像、数值／量子候选和独立重放；无证明特权。
- ci-build／公共 playground：事件驱动构建；ci-library／vci-inbox：公开胶囊和回执索引。

统一响应 nonce：`QF-LEAN-FED-20261123-01`。线路回复必须包含：

```json
{
  "nonce": "QF-LEAN-FED-20261123-01",
  "line": "LINE_NAME",
  "commit": "FULL_GIT_SHA",
  "package": "PACKAGE_ID",
  "toolchain": "EXACT_TOOLCHAIN",
  "verdict": "PASS | FAIL | OPEN | NOT_DELIVERED",
  "artifact_sha256": "64_HEX",
  "negative_results": [],
  "uncovered": [],
  "response_event": "EVENT_OR_PATH"
}
```

状态严格区分：`LOCAL_STAGED → TRANSPORT_OK → REMOTE_RECEIPT → LINE_ACK → VERIFIED_COMPLETE`。只写本地邮件是 `LOCAL_STAGED`；API 202 最多是 `TRANSPORT_OK`；没有线路回件不得写成 ACK。

## 8. 北星计划验收阶梯

| 阶段 | 交付 | 退出闸 |
|---|---|---|
| N0 资产与协议 | 包清单、身份、证据等级、负例 | 未验证包只登记，不激活 |
| N1 最小约束核 | 本仓 Lean＋capsule＋同步＋投影 | 本切片全部本地门禁通过 |
| N2 双线互证 | ASFA＋usrm 独立 attestation | 两线从原始源完整重建；冲突负例保持 |
| N3 领域列车 | mathlib 领域包与 HOLO 谱系接入 | 精确锁文件、声明对照、无隐式迁移 |
| N4 强验证 | 隔离 `lake check`、独立内核和跨机重放 | 明确 R2 报告；内核分歧失败关闭 |
| N5 自治研究 | 检索→形式化→证明→独立验证→投影→反向候选 | 预算、一次性票、死信、负结果和回执闭环 |
| N6 行业示范 | 可复现数学研究操作系统 | 公开定理索引、证据包、跨线复验和未覆盖边界 |

## 9. 当前实体切片与未覆盖项

当前实现包括：`lean/Qf` 六个锚定定理、真实 Lean 构建与公理日志、capsule／registry／projection 生成、独立 Python 判读、冲突零写入、幂等重放和事件驱动 GitHub workflow。

当前只声称本线 `FORMAL_R1`。usrm 和其他线路尚未因本切片而激活；`lake check` 的本地沙箱启动失败、独立内核、跨机重建、真实跨线 ACK 和外部 CI 均是开放项。Lean 通过也不证明自然语言命题、外部 QF-OS 正典或图谱投影具有预期非形式语义。

复验入口：

```bash
bash scripts/lean-federation-gate.sh FULL_IMPLEMENTATION_COMMIT /tmp/qf-lean-gate "$PWD"
python3 scripts/verify-lean-federation-python.py --self-test
```

## 10. QI-OS 原生协同面

全局自动协同直接复用 QI-OS 的 `qi-event/v1`、工单读回、答件不可覆写、异身份 crosscheck 和大小周天，不另造一套共识语义。Lean capsule 作为其 artifacts／requested_evidence 接入；QI-OS 的运输与身份判词不代替 Lean 证明，Lean 证明也不代替独立答件。

适配与独立在线判读见 `docs/QI_OS_WAVE.md`。当前 11 个工单均为 `DELIVERED`，但研究状态仍为 `OPEN`；任何自动回复都必须同时满足作者关联、事件 schema、原线绑定和独立 crosscheck。
