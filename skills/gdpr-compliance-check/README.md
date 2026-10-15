# 🔍 gdpr-compliance-check

> 欧盟 / 英国 GDPR 数据合规检查技能 —— 扫描数据里的个人数据，评估处理行为，校验隐私政策。
> An executable GDPR compliance toolkit: scan for personal data, assess processing practices,
> validate privacy notices.

[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-stdlib%20only-green)]()
[![Legal freshness](https://img.shields.io/badge/law%20verified-2026--10--15-orange)]()

---

## 💡 和其他 GDPR skill 有什么不同

GitHub 上大多数 GDPR skill 是**知识型**的：把条文和判断规则写进提示词，让模型自己推理。
这类 skill 有用，但结论不可复现——同样的输入，两次跑可能给出不同的判断。

这个 skill 是**执行型**的：

| | 知识型 skill | 本 skill |
|---|---|---|
| 怎么判断 | 模型读条文后推理 | 脚本扫描 + 规则引擎判定 |
| 结论可复现 | 否 | 是，同样的输入必然同样的输出 |
| 能出证据 | 依赖模型复述 | 输出结构化 JSON + Markdown，可直接归档 |
| 覆盖面 | 取决于模型记得多少 | 检测器清单可审计、可扩展 |

**模型负责理解意图和解释结论，脚本负责出可复现的事实。** 两者分工，不重叠。

---

## 🏗️ 三层检查模型

「数据是否合规」其实混着三个不同问题，分开才有解：

| 层 | 要回答的问题 | 工具 | 输出 |
|---|---|---|---|
| 📊 **数据层** | 到底有哪些个人数据？ | `scan_data.py` | PII 清单 + 风险分级 |
| ⚖️ **处理层** | 处理这些数据的行为合规吗？ | `assess.py` | 10 维度评分 + P0/P1/P2 整改清单 + ROPA 草稿 |
| 📄 **文档层** | 该告知的都说了吗？ | `docs_check.py` | Art.13/14 要素核对表 |

> **不扫数据就谈合规，等于没看病人就开药。** 第一层是必做的。

---

## 🚀 快速开始

```bash
# 1. 扫描数据
python3 scripts/scan_data.py ./your-data --json scan.json --md scan-report.md

# 2. 生成处理上下文模板，按实际情况填写
python3 scripts/assess.py --init-context context.json

# 3. 出差距报告 + ROPA 草稿
python3 scripts/assess.py --scan scan.json --context context.json \
    --out report.md --ropa ropa.md

# 4. 检查隐私政策
python3 scripts/docs_check.py privacy-policy.md
```

只依赖 Python 标准库（3.9+）。Excel 支持需要 `pip install openpyxl`，没装会自动跳过并提示。

---

## 📊 一、scan_data.py — 数据层扫描

### 支持格式

CSV / TSV / JSON / JSONL / NDJSON / 日志 / SQL / Markdown / XML / YAML / INI / ENV / Excel

### 用法

```bash
python3 scripts/scan_data.py <文件或目录> [选项]

选项:
  --json PATH       输出结构化结果（供 assess.py 消费）
  --md PATH         输出 Markdown 报告
  --max-rows N      每文件采样行数，默认 2000
  --max-bytes N     单文件大小上限，默认 25MB
  --redact          连脱敏样例都不输出（最高安全级）
  --quiet           只写文件，不打印终端摘要
```

⚠️ **退出码约定**：`0` 未发现 · `1` 发现个人数据 · `2` 运行错误。
**1 不是报错**，用 `&&` 串命令会被中断，脚本里请用 `;`。

### 识别的个人数据类型

| 风险 | 类型 | 条款 |
|---|---|---|
| 🔴 极高 | 健康/医疗、宗教信仰、政治观点/工会、性取向、种族/民族、基因数据 | Art.9(1) |
| 🔴 极高 | 生物识别特征 | Art.9(1) |
| 🔴 极高 | 犯罪记录/定罪数据 | Art.10 |
| 🔴 极高 | 身份证/国民注册号、护照号、社保号/税号 | Art.4(1)/Art.87 |
| 🔴 极高 | 支付卡号、银行账户(IBAN) | Art.4(1) |
| 🔴 极高 | 凭据/密钥（明文口令、API Key） | Art.32 |
| 🟠 高 | 电话号码、居住地址、精确位置坐标 | Art.4(1) |
| 🟠 高 | 未成年人(<16)个人信息 | Art.8 |
| 🟡 中 | 邮箱、IP 地址、MAC 地址、设备/广告标识符、出生日期 | Art.4(1) |
| 🟢 低 | 姓名、UUID/会话标识 | Art.4(1) |

### 三条关键设计

**1. 结构优先于正则**
CSV/JSON 先匹配字段名（内置中英双语词表），再用值正则兜底。字段名的信号远强于正则——
`birth_date` 一眼就知道是出生日期，靠正则从 `1985-03-12` 猜则要冒险。

**2. 敏感数据宁可误报，不可漏报**
- 普通类型：值正则命中率 ≥60% 才判定
- Art.9/Art.10 特殊类别：**命中 1 次即报**，交人工复核

实测效果：备注列 `notes` 里混着的 `trade union member`、`allergic to penicillin`
都能被抓出来——这类自由文本字段是敏感数据最常见的藏身处。

**3. 样例一律脱敏**
报告里绝不落明文个人数据。邮箱 → `zh***@example.com`，
手机 → `13******78`，GPS 坐标降到 ~1km 精度。
理由很实在：**报告本身也会变成一份待管数据**。

### 已规避的误报

| 误报场景 | 处理方式 |
|---|---|
| `ts`、`created_at` 等时间戳被判成出生日期 | 日期类只认字段名，列级判定不走值正则 |
| 版本号 `1.2.3.4` 被判成 IP | IPv4 正则收紧八位组范围 |
| 随机数字串被判成卡号 | Luhn 校验 |
| 随机字符串被判成 IBAN | mod-97 校验 |
| 假身份证号 | 18 位校验位验证 |

---

## ⚖️ 二、assess.py — 处理层评估

扫描只能告诉你"有什么"，合不合规还得看"怎么用"。

### 用法

```bash
# 生成上下文模板
python3 scripts/assess.py --init-context context.json

# 终端问答式收集（不想手填 JSON 时用这个）
python3 scripts/assess.py --scan scan.json --interactive

# 出报告
python3 scripts/assess.py --scan scan.json --context context.json \
    --out report.md --ropa ropa.md
```

> 上下文记录的是**事实**（有没有加密、留存多久、签没签 DPA），不是结论。
> 拿不准就留空或填 `false` —— 漏填会被判成待整改项，**比误填成"已合规"安全得多**。

### 评估的 10 个维度

合法性与法律依据 · 透明度与告知 · 数据最小化 · 存储限制 · 完整性与保密性 ·
数据主体权利 · 跨境传输 · 处理者与第三方 · 未成年人保护 · 问责与治理

### 整改分级

| 级别 | 时限 | 典型项 |
|---|---|---|
| 🔴 **P0** | 7 天内 | 特殊类别数据无 Art.9 例外 · 明文存储凭据 · 跨境无合法机制 · 未签 DPA · 无泄露响应机制 |
| 🟠 **P1** | 30 天内 | 无 LIA 平衡测试 · 未定义留存期限 · 无 DSAR 流程 · 无静态加密 · 无 ROPA |
| 🟡 **P2** | 90 天内 | 未做假名化 · 未评估 DPO 需求 · 员工培训 · 数据可携能力 |

### 内置判断规则

- **DPIA 触发**：EDPB 九项标准命中两项以上即应做
- **管辖分支**：`jurisdiction` 设为 `uk` 或 `both` 时，报告额外输出英国 GDPR 差异提示
- **时限表**：泄露通知 72 小时 · DSAR 响应 1 个月 · 间接获取后 1 个月内告知
- **处罚上限**：Art.83 两档（2000 万欧元/4% 与 1000 万欧元/2%）

### 输出示例

```
## 1. 总体结论

**综合合规评分：18.5 / 100 —— 高风险（建议立即整改）**

| 维度 | 得分 | 状态 |
|---|---|---|
| 合法性与法律依据 | 33.3 | 不符合 |
| 数据最小化 | 0.0 | 不符合 |
| ... |

### P0 立即整改（7 天内）（6 项）

| # | 检查项 | 条款 | 现状 | 整改措施 |
|---|---|---|---|---|
| 1 | 特殊类别数据具备例外事由 | Art.9(2) | 不符合 | 立即确认 Art.9(2) 例外；无法落到例外上的，停止处理并删除 |
| 2 | 未明文存储凭据/密钥 | Art.32 | 不符合 | 密码改用 bcrypt/argon2 加盐哈希 |
| ... |
```

---

## 📄 三、docs_check.py — 文档层检查

```bash
python3 scripts/docs_check.py privacy-policy.md --json docs.json
```

逐条核对 **Art.13/14 的 14 项必备告知要素**：

控制者身份与联系方式 · DPO 联系方式 · 处理目的与合法性基础 · 正当利益内容 ·
接收方类别 · 跨境传输及保障措施 · 留存期限 · 数据主体权利清单 · 撤回同意权 ·
向监管机构投诉权 · 是否强制提供及后果 · 自动化决策/画像说明 · 数据来源 · 安全措施

同时标出高风险表述：

| 风险表述 | 问题 |
|---|---|
| `indefinitely` / `永久保存` / `长期保留` | Art.5(1)(e) 留存期限过宽 |
| `与任何第三方共享` | Art.13(1)(e) 接收方范围过宽 |
| `继续使用即视为同意` | Art.4(11)/7 不满足自愿、明确 |
| 对删除权设置过度限制 | Art.17 需复核法律依据 |

支持 Markdown / TXT / HTML（自动剥离标签）。

---

## 📅 时效性

**法律类 skill 没有时效性管理就是定时炸弹。** 本 skill 的做法：

- `references/updates-2026.md` 独立维护立法进展，**标注最后核实日期 2026-10-15**
- 严格区分**现行有效**与**拟议未通过**
- SKILL.md 顶部写明铁律：**按现行有效的法规规划，不为草案重新设计**

当前关键结论：

| 事项 | 现行规则 | 别搞错成 |
|---|---|---|
| GDPR 实质条款 | 2026 年未变更 | — |
| 泄露通知期限 | **72 小时** | 拟议的 96 小时（未通过） |
| Art.30 记录豁免门槛 | **少于 250 名员工** | 拟议的 750/1000（未通过） |
| Cookie 同意 | ePrivacy 指令 + 国内法 | 拟议移入 GDPR（未通过） |
| 欧盟→美国传输 | DPF 有效，但**需保持 SCCs 备份** | 只依赖 DPF（CJEU 上诉待决） |

涵盖 UK GDPR（DUAA 2025）与欧盟的分叉、EU-US DPF 诉讼进展、
Uber 案（Art.22 人工审查）、GDPR 程序条例（2027-04 适用）等。

---

## 📁 目录结构

```
gdpr-compliance-check/
├── SKILL.md                          # 给 Agent 读的：触发条件、工作流、判断规则
├── README.md                         # 给人读的：本文件
├── scripts/
│   ├── scan_data.py                  # 数据层扫描（PII 识别与分级）
│   ├── assess.py                     # 处理层评估（差距分析 + ROPA）
│   └── docs_check.py                 # 文档层检查（Art.13/14 要素）
├── references/
│   ├── gdpr-articles.md              # 核心条款速查：义务 → 检查点
│   ├── lawful-basis.md               # Art.6 六选一决策树 + Art.9(2) 例外
│   ├── remediation-playbook.md       # 整改手册：动作、时限、DSAR 与泄露响应
│   └── updates-2026.md               # ⏰ 时效性与立法进展
└── assets/
    ├── consent-record-schema.md      # 同意记录表结构（举证用）
    └── dsar-response-template.md     # DSAR 响应回执模板
```

---

## 🔧 安装

```bash
cp -R gdpr-compliance-check ~/.workbuddy/skills/
```

或在仓库根目录运行 `bash install.sh gdpr-compliance-check`。

---

## 🚫 边界

- **不构成法律意见**，不替代 DPO 或律师判断。产出是**证据和待办**，不是法律结论
- **只读**：不修改、不删除、不外传被扫描的数据（已用 md5 校验确认）
- 扫描覆盖可识别的模式，**不保证覆盖所有形态的个人数据**
  （尤其是自由文本里隐含的、或需要语义理解才能识别的）
- 涉及监管调查、跨境诉讼、需要出具法律意见书的场景，请交给专业法律顾问

---

## ❓ FAQ

**Q: 扫描没发现数据，是不是就合规了？**
不是。扫描只覆盖可识别模式，还需结合处理行为（合法性基础、留存期限等）综合判断。
这正是第二层 `assess.py` 存在的意义。

**Q: 为什么有些项判定为"不适用"？**
规则引擎会根据扫描结果动态跳过无关检查项。比如没有跨境传输时，
跨境相关的检查项就标记为不适用，不拉低评分。

**Q: 能扫描生产数据库吗？**
建议先导出为 CSV/JSON 再扫。脚本是只读的，但对生产库直接跑 I/O 仍有风险，
且大文件会被 `--max-bytes` 跳过。

**Q: 报告里的样例为什么是脱敏的？**
因为报告本身也会变成一份待管数据。用 `--redact` 可以连脱敏样例都不输出。

**Q: 发现 P0 项怎么办？**
按整改手册执行。涉及 Art.9 特殊类别且无例外事由的，建议**立即停止处理**并评估删除。

---

MIT © [Ella (Yichen Shen)](https://github.com/tachikomaver2-ship-it)
