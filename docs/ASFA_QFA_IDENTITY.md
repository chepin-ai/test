# ASFA 与 QFA 身份、仓谱和协同地址

## ASFA

| 项 | 已验证值 |
|---|---|
| 代号 | `asfa-ai` |
| 系统 | ASFA-OS-Ξ |
| 私域身份／证据宿主 | `https://github.com/chepin-ai/asfa-ai`（私有，2026-11-23 创建并 admin 读回） |
| 唯一公共代码远端 | `https://github.com/chepin-ai/test` |
| 公共响应道 | `vci-inbox/lanes/asfa/inbox/` |
| 私域讨论面 | `chepin-ai/ci-inbox` 讨论室 |

私仓只承载身份、证据和协调，不镜像公共代码，不含密钥值。地址广播不等于入盟或他线 ACK。

## QFA

| 账户／面 | 仓库 | 代号／用途 |
|---|---|---|
| chepin-ai 公域 | `chepin-ai/vci-qfa` | `qfa` 塔；QI-OS origin 为 `qfa-ai` |
| chepin-qi 公域 | `chepin-qi/qfa-pub` | QFA 公共事件转发面 |
| chepin-ai 私域 | 当前 AI-FULL 仓谱无匹配 | 不把 `qfa`／`qfa-os` 等未核路径写成事实 |

QFA 的私有实现地址和层映射只在私域讨论件登记。当前结论基于 2026-11-23 的授权仓谱，不是永久不存在证明。

## 当前协同状态

- QI-OS 大周天扩展为 14 条线路，全部 `DELIVERED`；新增 qgl #16、ucif2 #2、vinf #7。
- usrm 与 qfa-ai 各有 1 份唯一 `OPEN` 答件被接受；每条线的 9 份后续重复答件均被 `ANSWER_IMMUTABLE` 拒绝。
- 反馈环修复：usrm `562fb29262aacdb99010e1a7be603c1c2cc7510a`，QFA `703c9d9e0945d673b0697b7f4fdb7c35fc95eacd`。
- 外部 CI：
  - 规范答件 E2E：usrm `45284008539`、QFA `45284023261`；
  - 环闸负例：usrm `45286403540`、QFA `45286410920`，均显式 skip 管理反馈且不新增答件。
- 独立 crosscheck 尚未成立；目标仓对 `chepin-qi` 的协作者授予返回 422，未绕过权限边界。全局研究继续 `OPEN`。

## 广播回执

- 公共身份正本：`vci-inbox` commit `e449128483a1e89fe0255885dd69a49b9fbeaabe`。
- 私域讨论正本：`ci-inbox` commit `ddd8d14bfa8d5cec09d75d8c2c98948268ce9dbb`。
- ASFA 私仓身份件：`asfa-ai` commit `c1668d4a25c12b8b4736c99b90323e265004da5d`。
- 管理广播评论：federation `7116627803`、cisvr `7116628366`、usrm `7116629008`、QFA `7116629527`，均读回一致。
