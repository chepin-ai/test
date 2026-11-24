# QI-OS 原生大周天与 Lean 证据联邦

## 设计边界

本仓不复制或改写 QI-OS 受信内核。`scripts/qios-lean-wave.py` 只负责：

1. 从指定 QI-OS 源树准备工作目录；
2. 加入 usrm peer 与 `WQ-QI-LEAN-FED-01`；
3. 将硬编码线路数的测试断言改为从实际 peers 配置机械计算；
4. 激活 `WAVE-QI-LEAN-FED-20261123-01`；
5. 通过 QI-OS 自己的 `federation_wave.py` 发送或轮询。

`scripts/verify-qios-wave-python.py` 是另一判读器，不调用 QI-OS 判读逻辑，独立检查：

- 每个远端 issue 的标题和 `QI-OS-WORKORDER-V1` canonical body；
- issue number 的严格整数类型；
- append-only `seq + prev-hash` 账本；
- 答件数量、open items、独立 crosscheck 和 promotion 边界；
- 弱关联 HMAC 事件的 event id、签名与本轮内核裁决一致性；远端签名有效而本轮出现 `AUTH_SIGNATURE`／`AUTH_UNAVAILABLE` 或缺失裁决时，独立判读同样失败关闭。

基础设施判读 `oracle_verdict=PASS` 与研究状态 `research_verdict=OPEN` 必须分开。没有全部必要答件和异身份 crosscheck，不得称为共识或闭环。

## 内容证明第三闸

双 PASS 只证明答件与复核的传输状态，不再直接晋级。只有主机侧 `record_content_proof` 能写入 `qi-lean-content-proof/v1` 收据；远端评论不能直接充当内容证明。收据绑定原答件、复核、验证主体、源提交、问题覆盖和 capsule／report／oracle／verifier 哈希。部分问题覆盖可以累积，只有覆盖预注册的全部 `content_required` 才清除对应内容债。

`scripts/qios-content-proof.py` 从指定完整提交生成全新 `git archive`，使用外部固定 runner 与独立 oracle 完成真实 Lean build／audit，再生成内容寻址收据。工作目录必须不存在，禁止复用中间产物或由候选源码替换判读器。当前证明等级仅为 `FORMAL_R1`，不是独立内核 R2。

## 命令

```bash
# 准备新实例；源树中的历史 runtime 不继承
python3 scripts/qios-lean-wave.py prepare \
  --source /path/to/qios-source \
  --work-dir /tmp/qios-lean-wave

# 只在运行时按名解析凭证；值不得出现在命令、文件或日志中
python3 scripts/qios-lean-wave.py send \
  --work-dir /tmp/qios-lean-wave --token-env GH_PAT_QI_FULL

python3 scripts/qios-lean-wave.py poll \
  --work-dir /tmp/qios-lean-wave --token-env GH_PAT_QI_FULL

# 独立在线读回；离线仅适用于本地结构检查，不能声称远端交付
python3 scripts/verify-qios-wave-python.py \
  --root /tmp/qios-lean-wave --token-env GH_PAT_QI_FULL \
  --out /tmp/qios-wave-oracle.json
```

## 当前实测

- QI-OS 原始源提交：`c13dcee8f67fce568e8b160be39c3d6ff8755736`。
- 原始归档独立测试：128 项通过；加入 usrm、qgl、ucif2、vinf、HMAC 与内容证明攻击回归后为 145 项通过。二次 expand 仍为 145 项通过，14 个既有订单保留，新订单为 0。
- 14 个工单全部远端读回 `DELIVERED`；其中公共入口包括 usrm issue #24、cisvr issue #2、federation issue #18、qgl #16、ucif2 #2、vinf #7。
- 最新独立在线判读：14/14 issue 标题与 canonical body 一致，账本 179 项完整；`protocol_answers_seen=22`、`unique_answers_accepted=2`、`independent_crosschecks=2`、`duplicate_answer_rejections=18`、`promotion=false`、`research_verdict=OPEN`。
- usrm 自动回复最初因作者关联与格式不合规被拒绝；修复后 usrm 与 qfa-ai 各有 1 份唯一 `OPEN` 答件被 QI-OS 接受。重复答件不覆盖首答，18 份均为 `ANSWER_IMMUTABLE`。
- 规范答件曾触发认证作者反馈环；usrm／QFA 已加入“协议答件与管理非答件不再触发 responder”的根因门禁。外部 CI 显式 skip 复核通过，协议答件数停止增长。
- 独立 crosscheck 由 QI 公共 CI 对原首答重算摘要并签发 HMAC；弱作者关联只让形态完整的签名事件进入内核，实际接受仍需正钥、正确事件 ID、正确摘要和异身份主体。错钥、错摘要、同主体与重复复核均在 145 项回归中失败关闭。

## 2026-11-24 外部内容闸实测

- 内容闸实现提交为 `de0c58f01c00384a79ab8b7537ecfd4c457d8405`。公共 CI `build-test-smoke` run `45298448970`、`lean-federation` run `45298449084`、`qios-content-gate` run `45298449022` 均为 `completed/success`。
- 作用域集成先证明 `double_pass_without_proof=OPEN`，再从该提交干净归档完成真实 Lean build／audit 和独立判读；记录收据后仅 `LOOP-484df50249d98668939d8a3a` 的 `WQ-QI-LEAN-FED-01` 为 PASS，全局仍为 OPEN／39 项开放债。这里的 `peer=lgt` 是作用域测试 loop，不是 lgt 线路提交真实研究答件。
- 内容收据 `eb2bfa14f43e2c13a4331e6f9c59a4d3c4ad00b6ccb7d7102d3b09aca2de1359` 的四项 artifact 绑定与 proof id 均已独立复算；重复收据与伪造 OPEN→PASS 篡改均失败关闭。Lean 侧仍为 6 declarations／6 attestations／36 projections，语义冲突控制真实到达 `statementConflict` 且 registry 不变。
- 原始公共 artifact 和逐项哈希见 `evidence/qios-content-gate-2026-11-24/`；这些结果不覆盖 usrm／QFA 的真实研究内容，也不建立 R2。

## 异常与开放项

- fresh prepare 初版曾把源归档的历史 runtime 复制进新工作目录，在离线准备阶段发现 21 个订单；现已改为激活前删除所复制 runtime。该版本未执行网络发送，未产生重复工单。
- 当前状态是 `DELIVERED／OPEN`，不是入盟、共识或跨线验证完成。usrm 管理回复 comment `7100156572` 明确标为非协议答件，不计入后续两份唯一 `OPEN` 答件。
- 管理修正单自身因包含协议标记文本也被轮询器列为 invalid；未造成晋级，但后续管理卡必须避免写入该标记，防止污染答件流。
- `ANOMALY-3`：两件既有 HMAC crosscheck 曾在错误密钥进程中以 `AUTH_SIGNATURE` 拒绝，独立判读也曾因未对拍本轮裁决而误给传输 PASS。远端事件与签名口径均未变化；正确密钥重放恢复两件原 `OPEN／errors=[]` 裁决，状态证据摘要保持 `2063bdae…030`。判读器修复提交 `0afc2211ab2183116504be135d67556e23f82bad` 新增三类发散负例，并在保存的真实异常快照上拒绝。详见 `evidence/qios-content-gate-2026-11-24/hmac-adjudication-divergence.json`。
- 私域投递、密钥指纹和完整仓谱只在私域证据区保存；公开证据仅保留公共 issue、聚合计数和脱敏结果。
