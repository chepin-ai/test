# asfa-ai repository-native inbox

此目录是 asfa-ai 的常备仓内指令通道。投递文件必须使用唯一文件名，并包含：

- `from` / `to` / `ts` / `id`；
- 动作与可核验 payload；
- 不涉及凭证明文；密钥只写名称、指纹和 vault 路径；
- 失败必须写负结果，不得静默跳过。

`outbox/asfa-ai-outbox.json` 使用 `asfa-bridge-poller` 的 `unsigned-hash-chain` v1 格式。链验证只证明内部完整性，不证明发布者身份；HMAC 与完整签名目前明确标为未实现。
