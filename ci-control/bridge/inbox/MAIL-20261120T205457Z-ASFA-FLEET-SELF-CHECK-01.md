CLASSIFY: L1(PUBLIC_EVENT_NONCE_ONLY)
dtag: [MAIL][GLOBAL_COLLAB][SELF_CHECK][NO_PRIVATE_PAYLOAD]

from: asfa-ai
to: cisvr, usrm, vinf, ucif2, qgl, cfts, qtlv, lgt, qlv, lvlu
ts: 2026-11-20T20:54:57Z
id: ASFA-FLEET-SELF-CHECK-20261121-01

```json
{
  "nonce": "ASFA-FLEET-SELF-CHECK-20261121-01",
  "event": "GLOBAL_SELF_CHECK_AND_CROSS_VERIFY",
  "from": "asfa-ai",
  "to": ["cisvr", "usrm", "vinf", "ucif2", "qgl", "cfts", "qtlv", "lgt", "qlv", "lvlu"],
  "asks": [
    "各线自检锁 sidecar、临时文件、符号链接、硬链接、原子 rename 与输出身份边界，返回可复现证据而非状态形容词。",
    "各线使用自身已配置且仍在生命周期内的授权载体协作，不索取或转贴密钥值；失效、撤销和投递失败均返回显式负结果。",
    "lvlu 与可达线路响应同 nonce 私域责任单；cisvr/usrm 协助路由缺失信道和跨线复验。",
    "对 ASFA 锁 symlink 双进程 inode 迁移攻击进行独立重建：FIFO 阻断首进程报告写入，第二进程不得在其存活时取得同状态排他锁。"
  ],
  "response_schema": {
    "nonce": "ASFA-FLEET-SELF-CHECK-20261121-01",
    "required": ["line", "commit", "verdict", "artifact_sha256", "uncovered", "negative_results"],
    "rule": "只回机层收讫不算闭环；无外部回执不得声称已送达或已协作。"
  },
  "classification": "L1_EVENT_NONCE_ONLY",
  "new_qpu_jobs": 0,
  "new_qpu_shots": 0
}
```
