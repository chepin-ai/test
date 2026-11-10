# 形式化结构、同构映射与攻击矩阵（2026-11-10）

## 1. 本轮绑定的三个结构

### 1.1 JSON 语义唯一性

对任意输入对象 `o`，其成员名先经 JSON 转义解码，再要求递归唯一：

```text
Unique({k₁:v₁, …, kₙ:vₙ}) ⇔ ∀i,j. decode(kᵢ)=decode(kⱼ) → i=j
                            ∧ ∀i. UniqueValue(vᵢ)
```

`strict_json` 在 schema 转换前执行此检查。Outbox、Registry 和 LedgerSnapshot 共用该入口；因此 `a` 与 `\u0061` 不能作为两个键绕过检查。该性质只表示**成员名唯一**，不表示数字、键排序和字符串转义已经满足完整 RFC 8785。

### 1.2 网络空间隔离

网络 `N` 的账本记为 `L_N`。CLI 恢复必须满足：

```text
schema = asfa-directive-ledger/v2
snapshot.network_name = N
```

否则加载失败，不能将旧 v1、无网络身份或其他网络的状态隐式迁移为 `L_N`。物理指令键仍为 `(session,id)`，网络维通过相互隔离且经过身份对拍的状态文件绑定；逻辑上不允许把 `L_A` 的 Duplicate／Conflict／Consumed 结果带入 `L_B`。

### 1.3 本地历史一致性

每个 session 保存检查点 `H=(h,z)`，其中 `h` 为已见高度，`z` 为该高度块哈希。对已通过当前文档完整验链的新链 `C=(h',z',blocks)`：

```text
h' < h                    ⇒ Rollback
h' = h ∧ z' ≠ z           ⇒ Fork
h' > h ∧ h > 0
  ∧ blocks[h-1].hash ≠ z  ⇒ Fork
其他情况                  ⇒ Accept(H := (h',z'))
```

检查点与指令、tombstone 一同进入原子快照。`ingest_outbox` 的顺序是：完整验链 → 指令来源复验 → 检查点对拍 → 指令入库 → 检查点提交。检查点失败发生在指令循环之前，故该 Outbox 的指令、 tombstone 和检查点均不改变。

这只是对完整链进行的 **O(n) 前缀一致性检查**，不是紧凑 Merkle consistency proof；只能发现相对于本机旧视图的异常，不能证明全局唯一历史。

## 2. 规范同构与真实覆盖边界

| 外部结构 | 可映射性质 | 本仓对应实现与测试 | 没有获得的外部保证 |
|---|---|---|---|
| [RFC 7493 I-JSON](https://www.rfc-editor.org/rfc/rfc7493.html)、[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785.html) | 跨解析器输入必须避免歧义；对象成员唯一 | `strict_json`；顶层、嵌套、转义同名键和 Registry 污染负例 | 完整 JCS 数字格式化、UTF-16 键排序和签名前规范字节 |
| [TUF 规范](https://theupdateframework.github.io/specification/latest/) | rollback、freeze、mix-and-match 防护需要版本／网络／过期边界 | 链高单调、旧前缀对拍、网络绑定、既有过期复核 | 签名 root、角色阈值、可信时钟和外部元数据版本锚 |
| [RFC 9162 CT v2](https://www.rfc-editor.org/rfc/rfc9162.html) | inclusion 与 consistency 是不同证明；checkpoint 是信任锚 | 当前文档逐块 inclusion 式重算；跨轮询旧头一致性检查 | Merkle inclusion/consistency proof、Signed Tree Head、日志签名 |
| [RFC 9942 SCITT 架构](https://www.rfc-editor.org/rfc/rfc9942.html)、[RFC 9943 SCITT VDS](https://www.rfc-editor.org/rfc/rfc9943.html) | append-only、non-equivocation、replayability 分层 | 本地追加一致性与可重放验证 | Signed Statement、Receipt、Transparent Statement、独立 Transparency Service |
| [C2SP tlog-witness](https://github.com/C2SP/C2SP/blob/main/tlog-witness.md) | witness 保存旧 checkpoint，验证新旧一致性后才更新 | 本地 `(height,latest)` 对拍与原子快照 | 独立 witness、签名与 cosignature、并发原子更新、分裂视图抑制 |
| [C2SP tlog-policy](https://github.com/C2SP/C2SP/blob/main/tlog-policy.md) | log／witness／quorum 是显式信任策略 | 当前只能表达“无 witness 的本地模式” | quorum；不能把 `quorum none` 包装成分裂视图防护 |
| [A2A 官方规范](https://github.com/a2aproject/A2A/blob/main/docs/specification.md) | Agent Card 可选 JWS；签名前使用 JCS；每次操作需要授权边界；Webhook 需要 SSRF 与重放考虑 | 为后续 Agent 身份和 URL 策略提供协议映射 | 本仓不是 A2A 实现，没有 Agent Card、JWS、任务授权或 Webhook 安全模块 |

C2SP 链接是 `main` 开发版，不称为稳定标准。A2A 签名 Agent Card 也只能证明相应卡片的签名完整性，不能自动证明后续任务、指令或履约结果可信。

前沿研究线索：[Signed but Not Safe: Requirement Integrity in Multi-Agent LLM Handoffs](https://arxiv.org/abs/2611.07483) 将问题进一步推进到“交接任务要求是否完整”。本仓尚未实现逐条 requirement 签名、授权范围证明或任务级语义完整性，不能把该论文列为已复现成果。

## 3. 攻击—实现—证据矩阵

| 攻击／碰撞 | 预注册拒绝条件 | 自动化对应 |
|---|---|---|
| 顶层重复 `session` | schema 和链处理前返回 `invalid_json` | `duplicate_json_members_are_rejected_before_schema_or_chain_processing` |
| 区块指令内重复 `action` | 不允许不同解析器选择 Harm／Ping 两种语义 | 同上 |
| `a` 与 `\u0061` | 解码后判重并拒绝 | `strict_json::tests::rejects_duplicate_members_at_every_depth`；Python oracle `escaped_duplicate_member` |
| Registry 重复 `network_name` | CLI 非零退出，不创建 state／report | `cli_duplicate_registry_member_does_not_create_state` |
| Snapshot 重复字段 | `InvalidData`，不恢复 | `snapshot_parser_rejects_duplicate_members` |
| 网络 B 复用网络 A 的 state | 网络对拍失败，原 state 字节不变，不生成新报告 | `cli_cross_network_state_reuse_fails_without_overwrite` |
| 合法同链重读／延长 | 重读为 Duplicate；延长保留旧前缀并入新指令 | `checkpoints_accept_extension_and_reject_rollback_and_forks_without_mutation` |
| 新链高度低于旧高度 | `Rollback`，指令与检查点不变 | 同上 |
| 同高不同 latest | `Fork`，无部分应用 | 同上 |
| 更高链但改写旧高度块 | `Fork`，不能借“更长”绕过 | 同上 |
| 重启后遇到分叉 | v2 快照恢复检查点后仍拒绝 | 同上，实际 `save_atomic`＋`load_for_network` |
| 后续区块伪造来源 | 整份 Outbox 零入库，检查点也为零 | `ingest_outbox_does_not_partially_apply_a_later_forged_block` |
| 跨语言摘要／Unicode 对应 | Python 生成向量由 Rust 接受；Python 独立复算同一向量 | `python_generated_non_ascii_chain_verifies_in_rust`；`scripts/verify-outbox-python.py` |

## 4. JCS 候选包评估与不采用结论

检索到 `serde_jcs 0.2.0`、`jcs-canonicalize 0.2.1`、`serde_json_canonicalizer 0.4.1`。本轮只评估，没有把任何候选加入本仓依赖。

独立运行 `jcs-canonicalize 0.2.1` 自带测试，14 项通过，包括其 vendored Cyberphone 参考语料、非 BMP 键的 UTF-16 排序和 ECMAScript 数字边界。该结果只证明候选包自身测试通过，不证明与本仓 V1 兼容。

不直接替换 `payload_digest` 的原因：

1. 当前 V1 哈希域和既有公开文档必须先保持兼容，不能在原域名下静默改变字节语义。
2. 候选包文档明确说明重复键采用 last-value-wins，仍需本仓的严格前置门禁。
3. 候选包文档明确说明超出 double 精确整数范围的输入会舍入；本仓含 `u64` 时间戳、nonce 和过期字段，不能接受静默舍入。
4. 完整升级需要版本化 V2 哈希域、双实现官方向量、边界值拒绝策略和旧链重验矩阵，而不是增加一个依赖就宣布完成。

## 5. 仍未关闭的攻击面与升级顺序

1. **整份快照回滚**：攻击者若能同时替换 state 和旧链，本地检查点也会回到旧值。需要外部单调计数器、签名 checkpoint 或独立 witness／quorum。
2. **发布者与指令授权**：无签名链不认证发布者；后续可映射 A2A/JWS 或 SCITT Signed Statement，但签名对象必须覆盖指令及授权范围，而非只签 Agent Card。
3. **多写者竞争**：`save_atomic` 只避免撕裂写，不提供锁或 compare-and-swap；两个 CLI 同时读旧状态仍可能丢失更新。当前契约是单写者。
4. **完整 JCS V2**：需先确定整数范围和跨语言规范字节，不可沿用 V1 哈希域。
5. **读取地址与正典身份**：jsDelivr 镜像与 raw 正本 URL 合法不同，不能简单强制 `Outbox.url == Session.url`；需要显式 `canonical_url` 和镜像 allowlist。
6. **网络请求安全**：SSRF、重定向、DNS  pinning、HTTP 降级和响应复杂性限制尚未形成完整策略。
7. **可信时间**：`--now` 是可测试的本地输入，不是可信时间源；过期检查不能替代 TUF 式签名根和时间策略。
8. **紧凑证明与后量子 witness**：Merkle consistency proof、witness cosignature、ML-DSA-44 均只属后续研究，不在当前代码路径。

## 6. 独立判读器范围

`scripts/verify-outbox-python.py` 不用 Rust 中间产物，独立执行 UTF-8／重复键解析、V1 负载摘要、逐块哈希、latest 和指令来源检查，并对已知答案与篡改负例自证。为避免 Python 与 Rust 浮点格式差异，它明确只接受无浮点且整数落在 `serde_json` 整数范围内的 V1 子集；其 canonical bytes **不是 RFC 8785 JCS**。
