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
- 答件数量、open items、独立 crosscheck 和 promotion 边界。

基础设施判读 `oracle_verdict=PASS` 与研究状态 `research_verdict=OPEN` 必须分开。没有全部必要答件和异身份 crosscheck，不得称为共识或闭环。

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
- 原始归档独立测试：128 项通过；加入 usrm、qgl、ucif2、vinf 后的配置驱动测试同为 128 项通过。
- 14 个工单全部远端读回 `DELIVERED`；其中公共入口包括 usrm issue #24、cisvr issue #2、federation issue #18、qgl #16、ucif2 #2、vinf #7。
- 独立在线判读：14/14 issue 标题与 canonical body 一致，账本完整；`protocol_answers_seen=20`、`unique_answers_accepted=2`、`duplicate_answer_rejections=18`、`promotion=false`。
- usrm 自动回复最初因作者关联与格式不合规被拒绝；修复后 usrm 与 qfa-ai 各有 1 份唯一 `OPEN` 答件被 QI-OS 接受。重复答件不覆盖首答，18 份均为 `ANSWER_IMMUTABLE`。
- 规范答件曾触发认证作者反馈环；usrm／QFA 已加入“协议答件与管理非答件不再触发 responder”的根因门禁。外部 CI 显式 skip 复核通过，协议答件数停止增长。

## 异常与开放项

- fresh prepare 初版曾把源归档的历史 runtime 复制进新工作目录，在离线准备阶段发现 21 个订单；现已改为激活前删除所复制 runtime。该版本未执行网络发送，未产生重复工单。
- 当前状态是 `DELIVERED／OPEN`，不是入盟、共识或跨线验证完成。usrm 管理回复 comment `7100156572` 明确标为非协议答件，不计入后续两份唯一 `OPEN` 答件。
- 管理修正单自身因包含协议标记文本也被轮询器列为 invalid；未造成晋级，但后续管理卡必须避免写入该标记，防止污染答件流。
- 私域投递、密钥指纹和完整仓谱只在私域证据区保存；公开证据仅保留公共 issue、聚合计数和脱敏结果。
