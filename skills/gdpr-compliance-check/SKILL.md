---
name: gdpr-compliance-check
description: 欧盟 GDPR 数据合规检查。当用户要求检查数据/数据库/日志/表格/隐私政策是否符合 GDPR、评估个人数据处理活动合规性、识别或清点 PII 敏感数据（邮箱/手机/身份证/银行卡/IP/位置/健康等）、准备 ROPA 处理活动记录或 DPIA 影响评估、处理数据主体权利请求（DSAR/删除/可携/反对）、排查跨境传输风险、核查同意机制，或提到 GDPR、个人数据保护、数据合规、隐私合规、PII 扫描、数据最小化、留存期限时使用。可扫描 CSV/TSV/JSON/JSONL/日志/SQL/Excel/HTML，按 Art.4/Art.9 分级并生成差距报告与整改清单。
agent_created: true
---

# GDPR 合规检查

> **法律时效性：2026-10-15**
> GDPR 实质条款 2026 年未变更，但周边立法极为活跃，且大量"新规"**尚未通过**。
> 涉及跨境传输、英国主体、自动化决策、AI 处理，或用户问「最新规定是什么」时，
> **先读 `references/updates-2026.md`** 再作答。
>
> 铁律：**按现行有效的法规规划，不为草案重新设计。**
> 泄露通知仍是 72 小时（不是拟议的 96），ROPA 豁免仍是少于 250 名员工（不是 750）。

把「数据是否合规」拆成三层，各层用一个脚本解决。**不要跳过第一层直接下结论**——
没扫过数据就谈合规，等于没看病人就开药方。

| 层 | 问题 | 工具 |
|---|---|---|
| 数据层 | 有哪些个人数据？ | `scan_data.py` |
| 处理层 | 处理这些数据的行为合规吗？ | `assess.py` |
| 文档层 | 该说的都说了吗？ | `docs_check.py` |

## 何时用 / 何时不用

**用**：数据资产盘点、上线前合规自查、隐私政策补齐、DSAR 响应准备、收购/接管前的数据尽调、
把欧盟用户数据迁出或迁入前的评估。

**不用**：需要出具法律意见书、应对监管正式调查、处理已发生的跨境诉讼——
这些交给数据保护法律顾问。本技能的产出是**证据和待办**，不是法律结论。

## 工作流

### 1. 扫描数据（必做）

```bash
PY=/Users/yc/.workbuddy/binaries/python/versions/3.13.12/bin/python3
SKILL=~/.workbuddy/skills/gdpr-compliance-check

$PY $SKILL/scripts/scan_data.py <数据文件或目录> --json scan.json --md scan-report.md
```

- 支持 CSV / TSV / JSON / JSONL / 日志 / SQL / Markdown / XML / Excel（需 `pip install openpyxl`）
- **结构优先**：CSV/JSON 先看字段名再校验值，字段名信号远强于正则
- 敏感类别（Art.9/Art.10）**命中即报**，宁可误报也不漏报，交人工复核
- 样例一律脱敏，报告里不落明文个人数据
- 大文件自动跳过并列出原因，用 `--max-bytes` 调上限

### 2. 生成并填写处理上下文

```bash
$PY $SKILL/scripts/assess.py --init-context context.json   # 生成模板，人工填写
$PY $SKILL/scripts/assess.py --scan scan.json --interactive # 或终端问答式收集
```

上下文记录的是**事实**（是否加密、留存多久、有无 DPA），不是结论。
拿不准就填 `false`/留空——漏填会被判成待整改项，比误填成"已合规"安全得多。

### 3. 出差距报告

```bash
$PY $SKILL/scripts/assess.py --scan scan.json --context context.json \
    --out report.md --ropa ropa.md
```

产出：10 个维度评分 + P0/P1/P2 分级整改清单 + ROPA 草稿。

### 4. 检查隐私政策（若适用）

```bash
$PY $SKILL/scripts/docs_check.py privacy-policy.md --json docs.json
```

逐条核对 Art.13/14 的 14 项必备告知要素，并标出「无限期保留」等高风险表述。

## 输出约定

- 报告统一 Markdown，可直接交付或贴进工单
- 整改项按 P0（7 天）/ P1（30 天）/ P2（90 天）分级
- 每条整改项必须带**条款依据**和**可执行动作**，不写"加强管理"这类空话
- 每份报告结尾保留免责声明

## 关键判断规则（速查）

- **没扫到数据 ≠ 合规**：扫描只覆盖可识别模式，还需结合处理行为判断
- **合法性基础六选一**（Art.6）：同意 / 合同 / 法律义务 / 重大利益 / 公共任务 / 正当利益；
  选正当利益必须补 LIA 平衡测试
- **敏感数据原则禁止**（Art.9）：健康、宗教、政治、工会、性取向、种族、基因、生物识别，
  必须落到 Art.9(2) 例外事由上，否则停止处理
- **IP 地址是个人数据**：CJEU Breyer 案（C-582/14）
- **IP + 设备 ID 等组合标识符**：单独低风险，组合后识别力骤增，按 high 处理
- **跨境传输三选一**：充分性认定（Art.45）/ SCCs（Art.46）/ BCRs（Art.47），
  用 SCCs 还需做 TIA（Schrems II）
- **DPIA 触发**：EDPB 九项标准命中两项以上即应做
- **时限**：泄露通知 72 小时（Art.33）、DSAR 响应 1 个月（Art.12(3)）、
  间接获取后 1 个月内告知（Art.14(3)）
- **自动化决策**（Art.22）：完全自动化且产生法律/类似重大影响的决策，
  需**有意义的人工审查**并向数据主体说明逻辑与后果（Uber 案，2026-08，€8.2499 亿）
- **先分清生效 vs 拟议**：回答前确认依据是现行法还是草案。
  草案一律标注「拟议，未通过，现行义务不变」
- **涉及英国主体时不套用欧盟规则**：UK GDPR 经 DUAA 2025 已实质分叉
  （Recognised Legitimate Interests 免 LIA、传输标准 "not materially lower"、
  SRI 取代部分 DPO 要求），需做英国专项分析

## 参考文件

| 文件 | 用途 | 何时加载 |
|---|---|---|
| `references/gdpr-articles.md` | 核心条款速查：义务 → 检查点 | 需要引条款时 |
| `references/lawful-basis.md` | 合法性基础决策树与 Art.9 例外事由 | 判断 Art.6/Art.9 时 |
| `references/remediation-playbook.md` | 整改手册：动作清单、时限、DSAR 与泄露响应流程 | 出整改方案时 |
| `references/updates-2026.md` | **时效性与立法进展**：现行有效 vs 拟议未通过 | 涉及跨境/英国/AI/自动化决策，或问「最新规定」时 |
| `assets/consent-record-schema.md` | 同意记录表结构（举证用） | 设计同意机制时 |
| `assets/dsar-response-template.md` | 数据主体权利响应回执模板 | 处理 DSAR 时 |

## 边界

- 不构成法律意见，不替代 DPO 或律师判断
- 不修改、不删除、不外传被扫描的数据，默认只读
- 发现高危项（明文凭据、无合法基础的特殊类别数据）时，在报告中明确标 P0 并建议停止处理
