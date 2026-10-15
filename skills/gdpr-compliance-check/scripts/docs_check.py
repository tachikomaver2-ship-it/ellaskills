#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR Privacy Notice Checker — 检查隐私政策 / 告知文本是否覆盖 Art.13-14 必备要素。

定位：文本层面的「要素齐不齐」检查，不评价表述是否严谨。
数据层面的检查请用 scan_data.py，处理行为层面的检查请用 assess.py。

用法：
    python3 docs_check.py privacy_policy.md
    python3 docs_check.py privacy.html --json result.json
    python3 docs_check.py policy.txt --lang en        # 指定语言，收紧关键词库

退出码：0 无缺失 / 1 存在缺失或风险提示 / 2 运行错误
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

# --------------------------------------------------------------------------- #
# Art.13 / Art.14 必备要素
# --------------------------------------------------------------------------- #

@dataclass
class Element:
    key: str
    article: str
    title: str
    severity: str                 # P0 缺了通常直接不合规 / P1 重要
    keywords: list[str]
    hint: str                     # 缺失时的补写建议


ELEMENTS: list[Element] = [
    Element("controller", "Art.13(1)(a)", "控制者身份与联系方式", "P0",
            ["data controller", "controller", "we are", "responsible for", "contact us",
             "contact details", "registered office",
             "控制者", "数据控制者", "责任主体", "联系我们", "联系方式", "公司名称"],
            "写明公司全称、注册地址与可联系的邮箱。"),

    Element("dpo", "Art.13(1)(b)", "数据保护官联系方式", "P1",
            ["data protection officer", "dpo@", "our dpo",
             "数据保护官", "隐私保护负责人"],
            "如已设立 DPO，公布其邮箱；未设立可写明负责联系的部门。"),

    Element("purpose_basis", "Art.13(1)(c)", "处理目的与合法性基础", "P0",
            ["purpose", "purposes", "legal basis", "lawful basis", "lawfulness",
             "why we process", "we process your",
             "处理目的", "使用目的", "合法性基础", "法律依据", "我们为何处理"],
            "逐项目的地列明「用途 → Art.6 依据」，不要只写概括性目的。"),

    Element("legitimate_interest", "Art.13(1)(d)", "正当利益的具体内容", "P2",
            ["legitimate interest", "legitimate interests", "balancing test",
             "正当利益", "合法利益"],
            "若依赖 Art.6(1)(f)，需说明具体是什么正当利益。"),

    Element("recipients", "Art.13(1)(e)", "接收方或接收方类别", "P0",
            ["recipient", "recipients", "third parties", "third party", "share",
             "disclose", "service providers", "processors",
             "接收方", "第三方", "共享", "披露", "服务商"],
            "列出接收方类别（如支付服务商、云服务商、物流），必要时列明具体主体。"),

    Element("transfer", "Art.13(1)(f)", "跨境传输及保障措施", "P0",
            ["third country", "outside the eea", "outside the eu", "international transfer",
             "adequacy decision", "standard contractual clauses", "sccs", "binding corporate rules",
             "跨境", "第三国", "境外", "充分性", "标准合同条款"],
            "说明是否向 EEA 外传输、目的国、机制（充分性认定 / SCCs / BCRs）及获取副本的方式。"),

    Element("retention", "Art.13(2)(a)", "留存期限或确定标准", "P0",
            ["retention", "retain", "storage period", "how long", "delete", "erasure period",
             "留存", "保留", "保存期限", "存储期限", "多久"],
            "给出具体期限或确定标准（如「账户注销后 30 天删除」），避免「我们会在必要期间保留」。"),

    Element("rights", "Art.13(2)(b)", "数据主体权利清单", "P0",
            ["right to access", "right of access", "rectification", "erasure",
             "right to be forgotten", "restriction of processing", "data portability",
             "right to object", "withdraw",
             "访问权", "查阅", "更正", "删除", "被遗忘", "限制处理", "可携", "反对"],
            "完整列出访问、更正、删除、限制、可携、反对六项权利及行使方式。"),

    Element("withdraw", "Art.13(2)(c)", "撤回同意的权利", "P1",
            ["withdraw your consent", "withdraw consent", "revoke consent",
             "撤回同意", "撤销同意", "取消授权"],
            "说明可随时撤回同意，且撤回不影响此前处理的合法性。"),

    Element("complaint", "Art.13(2)(d)", "向监管机构投诉的权利", "P0",
            ["supervisory authority", "lodge a complaint", "data protection authority",
             "监管机构", "投诉", "数据保护机构"],
            "写明可向所在国数据保护监管机构投诉（可附链接）。"),

    Element("mandatory", "Art.13(2)(e)", "是否强制提供及不提供的后果", "P1",
            ["statutory requirement", "contractual requirement", "necessary for",
             "required by law", "obliged to provide", "failure to provide",
             "法定要求", "合同要求", "必需", "必须提供", "不提供"],
            "区分「法定/合同强制」与「自愿提供」，并说明拒绝提供的后果。"),

    Element("automated", "Art.13(2)(f)", "自动化决策/画像与逻辑说明", "P1",
            ["automated decision", "automated decision-making", "profiling",
             "solely automated", "logic involved",
             "自动化决策", "自动决策", "画像", "算法"],
            "若存在自动化决策或画像，说明逻辑、重要性及预期后果。"),

    Element("source", "Art.14(2)(f)", "数据来源（非直接收集时）", "P1",
            ["we obtained", "source of the data", "collected from", "publicly available",
             "数据来源", "获取渠道", "来源"],
            "间接获取数据时，说明数据来自何处。"),

    Element("security", "Art.32", "安全措施说明", "P2",
            ["security measures", "encryption", "safeguards", "technical measures",
             "安全措施", "加密", "保护措施"],
            "简要说明技术与组织安全措施（加密、访问控制、审计等）。"),
]

# 危险信号：出现即提示复核
RED_FLAGS: list[tuple[str, str, str]] = [
    ("indefinite_retention", r"(indefinitely|for as long as necessary|永久保存|长期保留)",
     "Art.5(1)(e)：留存期限表述过于宽泛，需给出具体期限或确定标准。"),
    ("blanket_sharing", r"(any third part(y|ies)|share with (our )?partners|与任何第三方共享)",
     "Art.13(1)(e)：接收方范围过宽，需明确类别或具体主体。"),
    ("no_rights_guarantee", r"(we (may|will) not|无法保证).{0,40}(delete|remove|删除)",
     "Art.17：对删除权设置过度限制，需复核是否有法律依据。"),
    ("consent_bundling", r"(by (using|continuing)|继续使用即视为).{0,30}(consent|同意)",
     "Art.4(11)/7：以「继续使用即视为同意」不满足自愿、明确的要求。"),
]


def strip_html(text: str) -> str:
    text = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = re.sub(r"&nbsp;?", " ", text)
    text = re.sub(r"&amp;", "&", text)
    return text


def load_text(path: Path) -> str:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() in {".html", ".htm"}:
        raw = strip_html(raw)
    return raw


def check(text: str, lang: Optional[str] = None) -> dict:
    lower = text.lower()
    results, missing, weak = [], [], []

    for el in ELEMENTS:
        hits = [kw for kw in el.keywords if kw.lower() in lower]
        if hits:
            status = "present"
        else:
            status = "missing"
            missing.append(el)
        results.append({
            "key": el.key, "article": el.article, "title": el.title,
            "severity": el.severity, "status": status,
            "matched": hits[:5], "hint": el.hint,
        })

    flags = []
    for name, pattern, advice in RED_FLAGS:
        if re.search(pattern, lower, re.I):
            flags.append({"name": name, "advice": advice})

    p0_missing = [e for e in missing if e.severity == "P0"]
    return {
        "tool": "gdpr-docs-check",
        "version": "1.0",
        "elements": results,
        "missing_count": len(missing),
        "p0_missing": [{"article": e.article, "title": e.title, "hint": e.hint} for e in p0_missing],
        "red_flags": flags,
    }


def render_markdown(result: dict, source: str) -> str:
    L = [f"# 隐私政策告知要素检查（GDPR Art.13-14）", "",
         f"- 文件：`{source}`",
         f"- 缺失要素：{result['missing_count']} / {len(result['elements'])}", ""]

    L += ["## 检查结果", "", "| 状态 | 条款 | 要素 | 建议 |", "|---|---|---|---|"]
    icon = {"present": "存在", "missing": "缺失"}
    for e in result["elements"]:
        L.append(f"| {icon[e['status']]} | {e['article']} | {e['title']} | {e['hint']} |")
    L.append("")

    if result["p0_missing"]:
        L += ["## 必须补齐（P0）", ""]
        for e in result["p0_missing"]:
            L.append(f"- **{e['title']}**（{e['article']}）：{e['hint']}")
        L.append("")

    if result["red_flags"]:
        L += ["## 风险表述提示", ""]
        for f in result["red_flags"]:
            L.append(f"- {f['advice']}")
        L.append("")

    L += ["---", "", "> 本检查仅覆盖「告知要素是否出现」，不评估表述的严谨性与可执行性。"]
    return "\n".join(L)


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="GDPR 隐私政策告知要素检查器")
    p.add_argument("path", help="隐私政策文件（.md / .txt / .html）")
    p.add_argument("--json", dest="json_out", help="输出 JSON 结果路径")
    p.add_argument("--md", dest="md_out", help="输出 Markdown 报告路径")
    p.add_argument("--lang", choices=["zh", "en"], help="文档语言（用于收紧关键词库）")
    args = p.parse_args(argv)

    path = Path(args.path).expanduser()
    if not path.exists():
        print(f"[错误] 文件不存在: {path}", file=sys.stderr)
        return 2

    text = load_text(path)
    result = check(text, args.lang)

    print(render_markdown(result, str(path)))

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"\n[已写入] JSON → {args.json_out}")
    if args.md_out:
        Path(args.md_out).write_text(render_markdown(result, str(path)), encoding="utf-8")
        print(f"[已写入] Markdown → {args.md_out}")

    return 1 if (result["missing_count"] or result["red_flags"]) else 0


if __name__ == "__main__":
    sys.exit(main())
