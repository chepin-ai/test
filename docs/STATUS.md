# 实现状态（本轮实测证据：2026-11-14）

## 已有实测

- 实现提交为 `88a92e3778a3664f62835aa1746f21b9b831433c`（`feat(bridge): add bounded QF-OS wave planning`）。78 个 Rust 单元／集成测试通过：bridge 单元 27、bridge 集成 37、kernel 11、userspace 3，失败为 0。
- 从该提交的 Git 归档解到无 `.git` 的干净目录，并使用空 `CARGO_TARGET_DIR` 完整执行 `scripts/build-all.sh`。格式检查、Clippy 零警告、78 项测试、凭据扫描、Outbox／Policy／Wave Python 独立判读、波次临时重建与 fixture 字节对拍、认知示例和 CLI 烟测均通过。
- 干净归档 SHA-256 为 `f25eefdcbd83f3bdbf8e9dcb592673d33ed39f310325dc0e45a92d8d53ea3602`，干净重建二进制 SHA-256 为 `e6cbf30c7cc47467696894f5ab1177f603e30ba3267e698b02be92b73ac4f2d6`；五组旧新攻击使用同一干净二进制重跑并全部通过。
- 认知示例精确输出为 `skill_output={"sum":42}; edge=1; matches=[1]`。CLI 烟测为 `total=3, verified=1, failed=2`，两个失败是故意设置的非法 JSON 和缺失文件；v3 烟测状态策略摘要为 `d7bb090c4022b10a3f46ca236315cd96a77091ca0edeac038fac4016245d6a19`。
- 综合机器证据为 `evidence/attack-consistency-2026-11-14.json`，SHA-256 为 `1cd3f9341c83ef647971be2c7c7077466a0bcfac692bb58b3a7de5d92275b108`。其 10 项 artifact 的路径、字节数与 SHA-256 已独立复算，且差分新端哈希与干净重建二进制一致。

## 本轮新增安全性质

1. **有界轮询扇出**：Registry 除 2 MiB 字节上限外，最多 64 个 session；第 65 个会话导致任何 socket I/O 前非零失败。
2. **有界持久队列**：pending、tombstone、单 Outbox 已验证指令分别硬限 4096、16384、1024；CLI 参数只能调低，缺值或试图调高均失败。
3. **容量事务**：每份 Outbox 在克隆账本中暂存入库；任一容量超限会丢弃整个批次，不提交前面的成功前缀。恢复超基数 snapshot 和写出超 16 MiB 也失败关闭。
4. **消费不丢任务**：tombstone 满时，消费在删除 pending 前失败；原状态字节保持不变，待办仍可后续处理。
5. **协作写者排他锁**：`--state` 在加载前取得稳定 `<state>.lock` sidecar 的 OS 排他锁并持有到输出结束；竞争进程非零退出。它只覆盖使用相同词法路径的协作 CLI，不是分布式锁。
6. **QF-OS 波次接口**：`qfos-wave-plan/v1` 从已验证账本生成来源轮转、全局／来源双配额、显式 deferred 的确定性计划，绑定 network、policy、完整 snapshot、Job 和来源计数。
7. **计划能力边界**：计划模式固定为 `plan-only-no-execution`；生成计划不改账本、不消费指令、不执行 action、不调用 Skill。`plan_hash` 只是完整性摘要，不是执行证明或签名。
8. **独立波次判读**：Python 从 Registry 与原始 snapshot 重建过滤、轮转、配额、计数和双摘要；篡改 Job 或账本绑定均拒绝。

既有严格 JSON、传输授权、禁重定向、正典 URL、网络＋策略绑定、完整验链后入库和历史检查点继续有效。无签名链、策略摘要、账本摘要和计划摘要均不认证发布者。

## 旧新 CLI 差分

旧端为前一提交 `143668c20a79d2bcde5d555bee15be6cf8da2c91` 的 Git 归档构建；新端为上述实现提交的干净归档构建。判据在实现前登记于 `evidence/qfos-fusion-preregister-2026-11-14.json`，原始结果见 `evidence/differential-2026-11-14.json`，其 SHA-256 为 `61d66e79c01b9433e9ac4ef3607a26ab699fa2ebfe50a23281e1a5e1b203d982`。

| 攻击 | 旧端实测 | 新端实测 |
|---|---|---|
| SAT-01：5 个 pending，新端 cap=4 | 返回 0，pending=5 | 返回 2，整批拒绝，state／report 均不创建 |
| SAT-02：连续消费制造 tombstone | 五次均返回 0，consumed=5、pending=0 | cap=2 后第三次返回 2，状态字节不变，consumed=2、pending=3 |
| SAT-03：以低 cap 恢复 5 项 snapshot | 返回 0 并接受 | 轮询前返回 2，状态不变且不生成报告 |
| SAT-04：65 个 HTTP session | 实际传输命中 65 次，report.total=65 | 返回 2，传输命中 0，state／report 不创建 |
| LCK-01：双进程消费不同 ID | 两端均返回 0，但最后只剩 1 个 tombstone，另一消费被丢失 | 锁竞争者返回 2 且零竞争网络命中；显式重试后 consumed=2，两项均保留 |

`PASS` 只表示五项预注册旧新判据成立，不证明非协作写者、跨主机锁、分布式 CAS 或全系统安全。

## QF-OS 融合实测与 QIOS 边界

静态向量包含两个来源、五条未过期指令、一条过期指令、一个通配目标和非 ASCII 载荷。以 `max_jobs=3`、`max_per_source=2` 生成计划：

```text
admitted = [a1, b1, a2]
a3 → deferred_source_quota
b2 → deferred_wave_quota
plan_hash = fefb2704c277115cf4f88e2215cfb7a10cb508694a43527c300700ed47003302
```

`evidence/wave-oracle-2026-11-14.json` 记录独立重建及两个篡改负例。构建门禁会从原始 fixture 重新生成 state／plan，并与提交字节 `cmp` 相等。

本轮只实现 QF-OS 的**计划面接口**。QF-OS 引擎波次的实际执行、租约、回执、失败重试、poison-message 死信、结果签名与 Skill 沙箱均未接入。QIOS 在仓内、已读在役定义和本轮精确公开检索中均未解析为本项目正典实体；搜索结果中的同名医疗或其他领域术语不是适配依据。因此当前没有 QIOS adapter、兼容性或互操作完成声称。

## 独立判读与跨语言勾稽

- `verify-outbox-python.py`：无浮点 V1 链重算、指令来源检查、已知答案和篡改自证；不是 RFC 8785 JCS。
- `verify-policy-python.py`：Registry 安全投影、策略摘要、三项自证和 live snapshot 对拍；fixture 摘要仍为 `d5805bd450f0778f996fd6094d3a1723114da35be1adee5ca8bd0f361a3c7a21`。
- `verify-wave-python.py`：从原始 snapshot 重建完整波次计划；两个篡改自证通过，范围为无浮点 qfos-wave-v1 子集，不是签名、执行或 QIOS 证明。

## 公网交叉验证

使用干净归档二进制，于 2026-11-14T08:14:05Z 轮询七端点：`asfa-ai=verified`；cfts／cisvr／qgl／ucif2／usrm 为 HTTP 404；vinf 因未知字段 `chain_len` 为 `invalid_schema`。原始报告见 `evidence/poll-2026-11-14.json`，SHA-256 为 `e303f1b73fcc2c10e0749c3c4d0c2275c1cb4714cb5c07cff3016dd387da2a30`。

公网 jsDelivr 镜像与仓内 Outbox 字节相等，SHA-256 均为 `c0df0e35f63b20049ab9da97fe80509ef918ae0e3b1ad79d5e5f9ac7e36f56b4`；两份均通过 Python 判读与篡改自证。该相等不表示远端 Git main 等于本地实现提交，也不认证发布者。详见 `evidence/public-python-oracle-2026-11-14.json`。

## 联邦、凭证与推送边界

最后已核验正典状态仍为历史记录 `asfa-ai = conditional`（2026-11-09）。本轮没有 cisvr ACK、正典升 active 或 KEY-SYNC-01 relay 完成回执；写入 Outbox 不等于真实投递或对方 ACK。

本地 remote 为 `https://github.com/chepin-ai/test.git`，不含明文凭证。此前泄露的 PAT 仍应撤销／轮换，当前没有 GitHub 侧撤销证据。最后成功远端读回仍是 2026-11-11 的 `c573dc496dc3caeab1f0f143373c80859ccd93d4`；本轮两次 `ls-remote` 分别出现 TLS 非正确终止和超时，不能声称已刷新远端状态。按最后本地跟踪引用，实现提交为 `ahead_by=8, behind_by=0`；最终推送与 evidence 提交后的对拍另以实际命令结果为准。没有本轮外部 CI 回执。

## 明确未实现与后续债

1. DNS rebinding／pinning、解析器意见不一致、连接时 IP 绑定与 DNS 超时覆盖；
2. 私网、loopback、link-local、cloud metadata 地址策略与外层 egress 隔离；
3. 全轮询总 deadline、每请求剩余时间收缩、应用自定义 JSON 深度／节点数和进程级内存预算；
4. 路径别名、非协作写者、跨主机锁语义、CAS、WAL 和原子 check-and-persist；
5. 整份快照回滚、分裂视图、签名 checkpoint、独立 witness／quorum；
6. 发布者与指令授权、可信时间；
7. 完整 JCS V2、Merkle consistency proof、后量子 witness；
8. QF-OS 引擎执行、租约、回执、死信和结果证明；QIOS 正典定义与适配器；
9. 联盟 active、cisvr ACK、KEY-SYNC-01、旧 PAT 撤销、本轮远端同步和外部 CI 回执；
10. Boot／裸机内核、WASM、TEE、ZK-SNARK／STARK、HoTT-ZK、涌现类型系统、量子调度、神经网络推理、Holo-Lang 与完整形式化安全证明。

## 形式化内容边界

`formal/coq/Chain.v` 仅证明列表高度为零当且仅当列表为空。它不是哈希链安全性证明，更不是操作系统或 QF-OS 波次执行的安全证明。历史 `Admitted` 占位文件已删除。
