# 同意记录表结构（Art.7(1) 举证用）

GDPR 要求控制者**能证明**取得了同意。没有记录 = 等于没取得。
以下为建议字段，可按存储选型改为关系表 / 文档 / 事件日志。

## 主表：consent_records

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| consent_id | string | 是 | 唯一标识（UUID） |
| subject_ref | string | 是 | 数据主体引用（用内部 ID，**不要存明文证件号**） |
| subject_type | enum | 是 | user / visitor / employee / guardian |
| purpose_code | string | 是 | 处理目的编码，与 ROPA 一致 |
| purpose_text | text | 是 | 展示给数据主体的目的原文 |
| lawful_basis | enum | 是 | 固定为 `consent` |
| notice_version | string | 是 | 告知文本版本号，可回溯当时说了什么 |
| notice_locale | string | 是 | 语言（如 `en-GB`、`zh-CN`） |
| channel | enum | 是 | web / app / email / paper / phone |
| consent_action | enum | 是 | granted / withdrawn / expired / renewed |
| is_explicit | boolean | 是 | 是否明示同意（Art.9 场景必须为 true） |
| granted_at | timestamp | 是 | 授予时间（含时区） |
| withdrawn_at | timestamp | 否 | 撤回时间 |
| expires_at | timestamp | 否 | 到期时间（建议设置，避免无限期同意） |
| ip_address | string | 否 | 存哈希或截断，避免留存完整 IP |
| user_agent_hash | string | 否 | 设备指纹哈希，非原文 |
| evidence_ref | string | 否 | 截图 / 表单快照的存放位置 |

## 关键实现要求

| 要求 | 说明 |
|---|---|
| 不可变 | 记录只追加不修改，撤回写新行 |
| 可回溯 | 保留 `notice_version`，能还原当时的告知内容 |
| 最小化 | 证明用途之外不留存多余信息；IP 建议哈希或截断 |
| 同步 | 撤回后需同步到所有处理者与下游系统 |
| 易撤回 | 撤回路径的便捷度应与授予时相当（Art.7(3)） |

## 禁止的做法

- 「继续使用本网站即视为同意」
- 拒绝按钮与接受按钮视觉上不对等（暗黑模式）
- 把同意与条款接受捆绑成一个勾选框
- 预勾选默认开启
- 无法撤回，或撤回只能发邮件到无人值守邮箱

## 与 ePrivacy 的关系

Cookie / 设备标识符的**存储与读取**受 ePrivacy 指令约束，
要求**事前同意**（先同意，后投放）； GDPR 则约束**后续的个人数据处理**。
两者叠加：非必要 Cookie 必须先取得同意才能写入。
