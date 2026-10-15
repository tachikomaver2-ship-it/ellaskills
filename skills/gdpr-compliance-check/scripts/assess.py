#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR Compliance Assessor — 基于扫描结果 + 处理上下文，生成合规差距报告与 ROPA 草稿。

与 scan_data.py 分工：
    scan_data.py  → 回答「有哪些个人数据」
    assess.py     → 回答「处理这些数据的行为是否合规」

用法：
    # 1) 生成处理上下文模板，人工填写
    python3 assess.py --init-context context.json

    # 2) 终端问答式收集上下文（适合边聊边填）
    python3 assess.py --scan scan.json --interactive --out report.md

    # 3) 基于已填好的上下文出报告
    python3 assess.py --scan scan.json --context context.json --out report.md --ropa ropa.md

退出码：0 正常 / 2 用法或运行错误
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

# --------------------------------------------------------------------------- #
# 上下文（处理活动的事实输入）
# --------------------------------------------------------------------------- #

CONTEXT_TEMPLATE: dict[str, Any] = {
    "_说明": "按实际处理活动填写；留空或 false 会被判为待整改项。",
    # 管辖：eu / uk / both。英国经 DUAA 2025 已与欧盟实质分叉，
    # 涉及 uk 时报告会额外输出 UK 差异提示，避免直接套用欧盟规则。
    "jurisdiction": "eu",
    "controller": {
        "name": "",                  # 控制者名称（公司 / 团队）
        "contact": "",               # 联系方式（邮箱 / 地址）
        "established_in_eu": False,  # 是否在欧盟境内设立机构
        "eu_representative": False,  # 若无欧盟机构但受 Art.3(2) 管辖 → 需 Art.27 代表
        "dpo": False,                # 是否已指定数据保护官（Art.37）
    },
    "processing": {
        "purpose": "",               # 处理目的，越具体越好
        "lawful_basis": "",          # consent / contract / legal_obligation / vital_interests / public_task / legitimate_interests
        "legitimate_interests_balancing": False,  # 选 legitimate_interests 时是否做过 LIA 平衡测试
        "special_category_basis": "",            # Art.9(2) 例外事由；无敏感数据填 "none"
        "purpose_limitation_reviewed": False,    # 是否审查过「目的外使用」
        "minimization_reviewed": False,          # 是否做过最小化评估
        "accuracy_measures": False,              # 是否有数据更新 / 纠错机制
    },
    "retention": {
        "defined": False,            # 是否定义了留存期限
        "days": 0,                   # 留存天数；0 表示未定义
        "deletion_verified": False,  # 到期是否真的删了（而非只标记）
    },
    "security": {
        "encryption_at_rest": False,
        "encryption_in_transit": False,
        "access_control": False,     # 最小权限 / 角色分离
        "pseudonymisation": False,   # Art.32(1)(a) 假名化
        "backup_restore_tested": False,
    },
    "data_subject_rights": {
        "process_defined": False,    # 是否有 DSAR 受理流程
        "sla_days": 0,               # 响应时限（月）；GDPR 要求 ≤1
        "channels": [],              # 受理渠道，如 ["email", "web form"]
        "identity_verification": False,
    },
    "cross_border": {
        "enabled": False,            # 是否向欧盟/EEA 境外传输
        "countries": [],             # 目的国
        "mechanism": "none",         # adequacy / sccs / bcrs / derogation / none
        "tia_done": False,           # 是否做过传输影响评估（Schrems II）
        "supplementary_measures": False,
    },
    "third_parties": {
        "shared": False,
        "dpa_signed": False,         # Art.28 数据处理协议
        "subprocessors": [],         # 次级处理者清单
    },
    "transparency": {
        "privacy_notice_published": False,
        "layered_notice": False,     # 是否分层展示（简版 + 完整版）
        "notice_languages": [],      # 面向数据主体的语言
    },
    "automated_decision": {
        "enabled": False,            # 是否存在自动化决策 / 画像
        "legal_effect": False,       # 是否产生法律影响或类似重大影响
        "human_review": False,
        "logic_explained": False,
    },
    "minors": {
        "involved": False,
        "age_verification": False,
        "guardian_consent": False,
    },
    "governance": {
        "ropa_exists": False,        # Art.30 处理活动记录
        "dpia_done": False,          # Art.35 影响评估
        "breach_register": False,    # Art.33(5)
        "staff_training": False,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def get(ctx: dict, dotted: str, default: Any = None) -> Any:
    cur: Any = ctx
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return default
        cur = cur[part]
    return cur


# --------------------------------------------------------------------------- #
# 检查项
# --------------------------------------------------------------------------- #

PASS, PARTIAL, FAIL, NA = "pass", "partial", "fail", "na"

SENSITIVITY_CN = {"critical": "极高", "high": "高", "medium": "中", "low": "低"}


@dataclass
class Check:
    id: str
    dimension: str
    article: str
    title: str
    severity: str                       # P0 / P1 / P2
    remediation: str
    verify: Callable[[dict, dict], str]  # (context, scan_summary) -> 状态


def _has_special(scan_summary: dict) -> bool:
    return any(k.startswith("special_") or k == "criminal" or k == "biometric_id"
               for k in scan_summary)


def _has(scan_summary: dict, *keys: str) -> bool:
    return any(k in scan_summary for k in keys)


CHECKS: list[Check] = [
    # ---------- 合法性基础 ----------
    Check("law-01", "合法性与法律依据", "Art.6", "已明确并记录了合法性基础", "P0",
          "在处理活动记录中写明具体的 Art.6 依据；若依赖正当利益，补一份 LIA（Legitimate Interests Assessment）平衡测试。",
          lambda c, s: PASS if get(c, "processing.lawful_basis") in
          {"consent", "contract", "legal_obligation", "vital_interests", "public_task", "legitimate_interests"}
          else FAIL),

    Check("law-02", "合法性与法律依据", "Art.6(1)(f)", "依赖正当利益时已做平衡测试", "P1",
          "补 LIA：说明利益正当性、处理的必要性、与数据主体权益的平衡结论。",
          lambda c, s: PASS if get(c, "processing.lawful_basis") != "legitimate_interests"
          or get(c, "processing.legitimate_interests_balancing") else
          (FAIL if get(c, "processing.lawful_basis") == "legitimate_interests" else NA)),

    Check("law-03", "合法性与法律依据", "Art.9(2)", "特殊类别数据具备例外事由", "P0",
          "立即确认 Art.9(2) 例外（明示同意 / 医疗目的 / 法律义务等）；无法落到例外上的，停止处理并删除。",
          lambda c, s: PASS if get(c, "processing.special_category_basis") not in (None, "", "none")
          else (FAIL if _has_special(s) else NA)),

    Check("law-04", "合法性与法律依据", "Art.7", "基于同意时可证明、可撤回", "P1",
          "保存同意的时间戳、版本与告知内容；提供与授予同等便捷的撤回通道（Art.7(3)）。",
          lambda c, s: (PASS if get(c, "processing.consent_withdrawable", False)
                        else (PARTIAL if get(c, "processing.lawful_basis") == "consent" else NA))),

    Check("law-05", "合法性与法律依据", "Art.10", "犯罪记录数据处理有法律授权", "P0",
          "仅在官方机关控制或法律明确授权下处理，否则删除。",
          lambda c, s: NA if "criminal" not in s else
          (PASS if get(c, "processing.criminal_legal_basis", False) else FAIL)),

    # ---------- 透明度 ----------
    Check("tra-01", "透明度与告知", "Art.13/14", "已发布隐私政策", "P0",
          "发布隐私政策；用 docs_check.py 校验 Art.13/14 必备要素是否齐全。",
          lambda c, s: PASS if get(c, "transparency.privacy_notice_published") else FAIL),

    Check("tra-02", "透明度与告知", "Art.12(1)", "以简洁、易懂的语言提供信息", "P1",
          "改为分层告知（简版摘要 + 完整版），避免长篇法务文本。",
          lambda c, s: PASS if get(c, "transparency.layered_notice") else
          (FAIL if get(c, "transparency.privacy_notice_published") else NA)),

    Check("tra-03", "透明度与告知", "Art.12(1)", "提供数据主体使用的语言版本", "P2",
          "按数据主体分布补充语言版本（如面向欧盟公民至少提供英文 + 主要成员国语言）。",
          lambda c, s: PASS if get(c, "transparency.notice_languages") else
          (FAIL if get(c, "transparency.privacy_notice_published") else NA)),

    Check("tra-04", "透明度与告知", "Art.27/3(2)", "无欧盟机构时已指定欧盟代表", "P1",
          "依据 Art.27 指定欧盟境内代表，并在隐私政策中公布其联系方式。",
          lambda c, s: NA if get(c, "controller.established_in_eu")
          else (PASS if get(c, "controller.eu_representative") else FAIL)),

    # ---------- 数据最小化 ----------
    Check("min-01", "数据最小化", "Art.5(1)(c)", "收集范围与处理目的相匹配", "P1",
          "逐字段追问「删掉它，目的还能否达成」；不能达成才保留。",
          lambda c, s: PASS if get(c, "processing.minimization_reviewed") else
          (FAIL if s else NA)),

    Check("min-02", "数据最小化", "Art.87", "未收集不必要的国民识别号码", "P0",
          "改用内部生成的替代 ID；确需处理国民识别号的，遵守成员国附加条件。",
          lambda c, s: NA if not _has(s, "national_id", "ssn")
          else (PASS if get(c, "processing.national_id_justified", False) else FAIL)),

    Check("min-03", "数据最小化", "Art.32", "未明文存储凭据/密钥", "P0",
          "密码改用 bcrypt/argon2 加盐哈希；API Key 移入密钥管理服务，日志中脱敏。",
          lambda c, s: NA if "credential" not in s
          else (PASS if get(c, "security.credential_hashed", False) else FAIL)),

    # ---------- 存储限制 ----------
    Check("ret-01", "存储限制", "Art.5(1)(e)", "已定义留存期限", "P1",
          "为每个数据类别设定具体期限（如注册后 24 个月未活跃即删除），写入隐私政策。",
          lambda c, s: PASS if get(c, "retention.defined") else (FAIL if s else NA)),

    Check("ret-02", "存储限制", "Art.17", "到期执行实际删除并可举证", "P1",
          "实现硬删除或安全匿名化（不可复原），保留删除日志作为 Art.5(2) 问责证据。",
          lambda c, s: NA if not get(c, "retention.defined")
          else (PASS if get(c, "retention.deletion_verified") else FAIL)),

    # ---------- 安全 ----------
    Check("sec-01", "完整性与保密性", "Art.32", "传输加密（TLS）", "P0",
          "全站启用 TLS 1.2+，禁用明文 HTTP，配置 HSTS。",
          lambda c, s: PASS if get(c, "security.encryption_in_transit") else (FAIL if s else NA)),

    Check("sec-02", "完整性与保密性", "Art.32", "静态加密", "P1",
          "数据库 / 备份启用静态加密，密钥与数据分离存储。",
          lambda c, s: PASS if get(c, "security.encryption_at_rest") else (FAIL if s else NA)),

    Check("sec-03", "完整性与保密性", "Art.32", "访问控制与最小权限", "P1",
          "按角色授权、默认拒绝，敏感数据访问留审计日志。",
          lambda c, s: PASS if get(c, "security.access_control") else (FAIL if s else NA)),

    Check("sec-04", "完整性与保密性", "Art.32(1)(a)", "敏感字段已假名化", "P2",
          "对邮箱 / 手机等标识符做假名化或令牌化，降低泄露后可识别性。",
          lambda c, s: NA if not (_has_special(s) or _has(s, "email", "phone"))
          else (PASS if get(c, "security.pseudonymisation") else PARTIAL)),

    # ---------- 数据主体权利 ----------
    Check("dsr-01", "数据主体权利", "Art.15-22", "已建立权利响应流程", "P1",
          "建立 DSAR 工单流程与责任人，覆盖访问、更正、删除、限制、可携、反对。",
          lambda c, s: PASS if get(c, "data_subject_rights.process_defined") else (FAIL if s else NA)),

    Check("dsr-02", "数据主体权利", "Art.12(3)", "响应时限 ≤ 1 个月", "P1",
          "设定 1 个月 SLA；复杂请求最多延长 2 个月且须在首月内告知理由。",
          lambda c, s: NA if not get(c, "data_subject_rights.process_defined")
          else (PASS if 0 < get(c, "data_subject_rights.sla_days", 0) <= 1 else FAIL)),

    Check("dsr-03", "数据主体权利", "Art.20", "支持数据可携（机器可读导出）", "P2",
          "提供 JSON / CSV 导出能力（仅适用于基于同意或合同、且自动化处理的数据）。",
          lambda c, s: NA if not get(c, "data_subject_rights.process_defined")
          else (PASS if get(c, "data_subject_rights.portability", False) else PARTIAL)),

    Check("dsr-04", "数据主体权利", "Art.12(6)", "请求时验证身份（且不过度收集）", "P2",
          "用已有账号体系验证身份；避免为了验证身份再索要新的身份证件。",
          lambda c, s: NA if not get(c, "data_subject_rights.process_defined")
          else (PASS if get(c, "data_subject_rights.identity_verification") else PARTIAL)),

    Check("dsr-05", "数据主体权利", "Art.22", "自动化决策已提供人工介入", "P0",
          "提供人工复核、表达异议与理解决策逻辑的通道（Art.13(2)(f)/15(1)(h)）。",
          lambda c, s: NA if not get(c, "automated_decision.enabled")
          else (PASS if get(c, "automated_decision.human_review") else FAIL)),

    # ---------- 跨境 ----------
    Check("xbd-01", "跨境传输", "Art.44-49", "存在合法传输机制", "P0",
          "按目的国选择机制：充分性认定（Art.45）/ SCCs（Art.46）/ BCRs（Art.47）。",
          lambda c, s: NA if not get(c, "cross_border.enabled")
          else (PASS if get(c, "cross_border.mechanism") in {"adequacy", "sccs", "bcrs"} else FAIL)),

    Check("xbd-02", "跨境传输", "Art.46/Schrems II", "已完成传输影响评估(TIA)", "P1",
          "评估目的国政府访问法律，记录补充措施（加密、密钥自持、透明度报告）。",
          lambda c, s: NA if not get(c, "cross_border.enabled")
          else (PASS if get(c, "cross_border.tia_done") else FAIL)),

    Check("xbd-03", "跨境传输", "Art.30", "已列明目的国与接收方", "P2",
          "在处理活动记录中列出接收方名称、目的国与传输机制。",
          lambda c, s: NA if not get(c, "cross_border.enabled")
          else (PASS if get(c, "cross_border.countries") else PARTIAL)),

    # ---------- 第三方 ----------
    Check("tp-01", "处理者与第三方", "Art.28", "已签署数据处理协议(DPA)", "P0",
          "与所有处理者签署符合 Art.28(3) 的 DPA，明确目的、期限、安全措施与审计权。",
          lambda c, s: NA if not get(c, "third_parties.shared")
          else (PASS if get(c, "third_parties.dpa_signed") else FAIL)),

    Check("tp-02", "处理者与第三方", "Art.28(2)", "次级处理者变更可控", "P2",
          "要求处理者变更次级处理者前通知，并保留反对权。",
          lambda c, s: NA if not (get(c, "third_parties.shared") and get(c, "third_parties.dpa_signed"))
          else (PASS if get(c, "third_parties.subprocessor_control", False) else PARTIAL)),

    # ---------- 未成年人 ----------
    Check("min-04", "未成年人保护", "Art.8", "涉及未成年人时已获监护人同意", "P0",
          "对 16 岁以下（部分成员国为 13-15 岁）用户取得监护人同意，并做合理努力验证。",
          lambda c, s: NA if not (get(c, "minors.involved") or "minor" in s)
          else (PASS if get(c, "minors.guardian_consent") else FAIL)),

    # ---------- 治理与问责 ----------
    Check("gov-01", "问责与治理", "Art.30", "已建立处理活动记录(ROPA)", "P1",
          "用 `--ropa` 生成草稿并按实际补充；ROPA 是监管检查的第一份索要文件。",
          lambda c, s: PASS if get(c, "governance.ropa_exists") else (FAIL if s else NA)),

    Check("gov-02", "问责与治理", "Art.35", "高风险处理已完成 DPIA", "P1",
          "按 EDPB 九项标准评估；命中两项以上即应做 DPIA 并留档。",
          lambda c, s: NA if not _dpia_required(c, s)
          else (PASS if get(c, "governance.dpia_done") else FAIL)),

    Check("gov-03", "问责与治理", "Art.33(5)", "已建立数据泄露登记与响应机制", "P0",
          "建立 72 小时响应流程（Art.33）+ 泄露登记册；对高风险泄露及时通知数据主体（Art.34）。",
          lambda c, s: PASS if get(c, "governance.breach_register") else (FAIL if s else NA)),

    Check("gov-04", "问责与治理", "Art.37", "已评估是否需要 DPO", "P2",
          "公共机构、大规模系统化监控、大规模敏感数据处理三类强制设立 DPO；其余建议指定负责人。",
          lambda c, s: PASS if get(c, "controller.dpo") else
          (PARTIAL if get(c, "controller.privacy_owner", False) else FAIL)),

    Check("gov-05", "问责与治理", "Art.39", "员工已接受数据保护培训", "P2",
          "对接触个人数据的岗位做年度培训并留记录。",
          lambda c, s: PASS if get(c, "governance.staff_training") else PARTIAL),
]


def _dpia_required(c: dict, s: dict) -> bool:
    """EDPB 九项标准：命中 2 项以上即推定需要做 DPIA。"""
    hits = 0
    hits += 1 if get(c, "processing.evaluation_or_scoring", False) else 0
    hits += 1 if get(c, "automated_decision.enabled") and get(c, "automated_decision.legal_effect") else 0
    hits += 1 if get(c, "processing.systematic_monitoring", False) else 0
    hits += 1 if _has_special(s) else 0
    hits += 1 if get(c, "processing.large_scale", False) else 0
    hits += 1 if get(c, "processing.dataset_matching", False) else 0
    hits += 1 if get(c, "minors.involved") or "minor" in s else 0
    hits += 1 if get(c, "processing.innovative_tech", False) else 0   # 含 AI / 生物识别
    hits += 1 if get(c, "processing.blocks_rights", False) else 0
    return hits >= 2


# --------------------------------------------------------------------------- #
# 维度与评分
# --------------------------------------------------------------------------- #

DIMENSIONS = [
    "合法性与法律依据",
    "透明度与告知",
    "数据最小化",
    "存储限制",
    "完整性与保密性",
    "数据主体权利",
    "跨境传输",
    "处理者与第三方",
    "未成年人保护",
    "问责与治理",
]

SEVERITY_LABEL = {"P0": "P0 立即整改（7 天内）", "P1": "P1 短期整改（30 天内）",
                  "P2": "P2 中期完善（90 天内）"}


@dataclass
class Assessment:
    context: dict
    scan: dict
    results: list[dict] = field(default_factory=list)

    def score(self, dimension: str) -> Optional[float]:
        vals = {"pass": 1.0, "partial": 0.5, "fail": 0.0}
        items = [r for r in self.results if r["dimension"] == dimension and r["status"] != NA]
        if not items:
            return None
        return round(sum(vals[r["status"]] for r in items) / len(items) * 100, 1)

    def overall(self) -> float:
        scores = [s for s in (self.score(d) for d in DIMENSIONS) if s is not None]
        return round(sum(scores) / len(scores), 1) if scores else 0.0

    def grade(self) -> str:
        s = self.overall()
        if s >= 85:
            return "基本符合（仍有改进空间）"
        if s >= 70:
            return "需改进"
        if s >= 50:
            return "存在显著差距"
        return "高风险（建议立即整改）"


# --------------------------------------------------------------------------- #
# DPIA 触发因素说明（供报告引用）
# --------------------------------------------------------------------------- #

DPIA_CRITERIA = [
    "评价或评分（含画像与预测）",
    "具有法律影响或类似重大影响的自动化决策",
    "系统性监控",
    "敏感数据或高度个人性数据",
    "大规模处理",
    "匹配或合并数据集",
    "弱势数据主体（如儿童、员工）",
    "创新技术或新组织方案（如 AI、生物识别）",
    "处理本身妨碍数据主体行使权利",
]

DEADLINES = [
    ("数据泄露通知监管机构", "知悉后 72 小时内", "Art.33(1)"),
    ("向数据主体通报泄露", "不得无故延迟（高风险时）", "Art.34"),
    ("响应数据主体权利请求", "1 个月内，最长可延 2 个月", "Art.12(3)"),
    ("首次通知数据主体（非直接收集）", "取得后 1 个月内", "Art.14(3)(a)"),
    ("个人信息更正 / 删除", "无不当延迟", "Art.16/17"),
]

FINE_TIERS = [
    ("最高 2000 万欧元或全球年营业额 4%（较高者）",
     "基本原则与合法性、同意、数据主体权利、跨境传输违规"),
    ("最高 1000 万欧元或全球年营业额 2%（较高者）",
     "安全措施、处理活动记录、DPIA、泄露通知、DPO 等义务"),
]


# --------------------------------------------------------------------------- #
# 交互问答
# --------------------------------------------------------------------------- #

class _InputAborted(Exception):
    """输入流结束或用户中断（Ctrl-D / Ctrl-C）；已收集的内容仍然有效。"""


def interactive_context(scan_summary: dict) -> dict:
    """终端问答收集上下文。"""
    ctx = json.loads(json.dumps(CONTEXT_TEMPLATE))
    print("\n处理上下文收集（直接回车 = 使用默认/跳过，Ctrl-D 提前结束）\n" + "-" * 60)

    def _read(prompt: str) -> str:
        try:
            return input(prompt)
        except (EOFError, KeyboardInterrupt):
            print()
            raise _InputAborted

    def ask(prompt: str, default: Any) -> str:
        raw = _read(f"{prompt} [{default}]: ").strip()
        return raw or str(default)

    def ask_bool(prompt: str, default: bool) -> bool:
        raw = _read(f"{prompt} ({'Y/n' if default else 'y/N'}): ").strip().lower()
        if not raw:
            return default
        return raw in {"y", "yes", "是", "true", "1"}

    def ask_choice(prompt: str, options: list[str], default: str) -> str:
        print(f"{prompt} 可选: {' / '.join(options)}")
        raw = _read(f"  选择 [{default}]: ").strip().lower()
        return raw if raw in options else default

    try:
        c = ctx["controller"]
        c["name"] = ask("控制者名称", "")
        c["contact"] = ask("联系方式", "")
        c["established_in_eu"] = ask_bool("是否在欧盟境内设有机构？", False)
        c["eu_representative"] = ask_bool("是否已指定 Art.27 欧盟代表？", False)
        c["dpo"] = ask_bool("是否已指定 DPO？", False)

        p = ctx["processing"]
        p["purpose"] = ask("处理目的", "")
        p["lawful_basis"] = ask_choice("合法性基础",
                                       ["consent", "contract", "legal_obligation",
                                        "vital_interests", "public_task", "legitimate_interests"],
                                       "consent")
        if p["lawful_basis"] == "legitimate_interests":
            p["legitimate_interests_balancing"] = ask_bool("是否已完成 LIA 平衡测试？", False)
        if _has_special(scan_summary):
            print("  [提示] 扫描发现疑似 Art.9 特殊类别数据，必须明确例外事由。")
            p["special_category_basis"] = ask("Art.9(2) 例外事由", "")
        p["minimization_reviewed"] = ask_bool("是否已完成数据最小化评估？", False)

        r = ctx["retention"]
        r["defined"] = ask_bool("是否已定义留存期限？", False)
        if r["defined"]:
            r["days"] = int(ask("留存天数", 365) or 365)
            r["deletion_verified"] = ask_bool("到期是否执行了实际删除？", False)

        s = ctx["security"]
        s["encryption_in_transit"] = ask_bool("是否启用传输加密(TLS)？", False)
        s["encryption_at_rest"] = ask_bool("是否启用静态加密？", False)
        s["access_control"] = ask_bool("是否实施最小权限访问控制？", False)
        s["pseudonymisation"] = ask_bool("敏感字段是否已假名化？", False)

        d = ctx["data_subject_rights"]
        d["process_defined"] = ask_bool("是否已建立权利响应流程？", False)
        if d["process_defined"]:
            d["sla_days"] = int(ask("响应时限(月)", 1) or 1)

        x = ctx["cross_border"]
        x["enabled"] = ask_bool("是否向欧盟/EEA 境外传输数据？", False)
        if x["enabled"]:
            x["countries"] = [t.strip() for t in ask("目的国(逗号分隔)", "").split(",") if t.strip()]
            x["mechanism"] = ask_choice("传输机制", ["adequacy", "sccs", "bcrs", "derogation", "none"], "sccs")
            x["tia_done"] = ask_bool("是否已完成 TIA 传输影响评估？", False)

        t = ctx["third_parties"]
        t["shared"] = ask_bool("是否与第三方共享数据？", False)
        if t["shared"]:
            t["dpa_signed"] = ask_bool("是否已签署 DPA？", False)

        a = ctx["automated_decision"]
        a["enabled"] = ask_bool("是否存在自动化决策/画像？", False)
        if a["enabled"]:
            a["legal_effect"] = ask_bool("是否产生法律或类似重大影响？", False)
            a["human_review"] = ask_bool("是否提供人工复核通道？", False)

        m = ctx["minors"]
        m["involved"] = ask_bool("是否涉及未成年人？", False)
        if m["involved"]:
            m["guardian_consent"] = ask_bool("是否已取得监护人同意？", False)

        g = ctx["governance"]
        g["ropa_exists"] = ask_bool("是否已建立 ROPA？", False)
        g["dpia_done"] = ask_bool("是否已完成 DPIA？", False)
        g["breach_register"] = ask_bool("是否已有泄露登记与响应机制？", False)
        g["staff_training"] = ask_bool("是否已开展员工培训？", False)

    except _InputAborted:
        print("[提示] 输入中断，使用已填写内容继续；未填写项按「未做」处理。")
    return ctx


# --------------------------------------------------------------------------- #
# 报告渲染
# --------------------------------------------------------------------------- #

def render_report(a: Assessment) -> str:
    ctx, scan = a.context, a.scan
    L: list[str] = []
    jur_label = {"eu": "欧盟 GDPR", "uk": "英国 GDPR（DUAA 2025）",
                 "both": "欧盟 GDPR + 英国 GDPR（需分别评估）"}.get(
        str(get(ctx, "jurisdiction", "eu")).lower(), str(get(ctx, "jurisdiction")))

    L += ["# GDPR 合规差距评估报告", "",
          f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}",
          f"- 适用法域：{jur_label}",
          f"- 控制者：{get(ctx, 'controller.name') or '（未填写）'}",
          f"- 处理目的：{get(ctx, 'processing.purpose') or '（未填写）'}",
          f"- 合法性基础：{get(ctx, 'processing.lawful_basis') or '（未填写）'}",
          f"- 数据来源扫描：{scan.get('files_scanned', 0)} 个文件"
          f"（根路径 `{scan.get('root', '-')}`）",
          ""]

    # ---- 结论 ----
    L += ["## 1. 总体结论", "",
          f"**综合合规评分：{a.overall()} / 100 —— {a.grade()}**", "",
          "| 维度 | 得分 | 状态 |", "|---|---|---|"]
    for d in DIMENSIONS:
        s = a.score(d)
        if s is None:
            L.append(f"| {d} | — | 不适用 |")
        else:
            tag = "符合" if s >= 85 else ("部分符合" if s >= 50 else "不符合")
            L.append(f"| {d} | {s} | {tag} |")
    L.append("")

    # ---- 数据清单 ----
    summary = scan.get("summary", {})
    if summary:
        L += ["## 2. 个人数据清单", "",
              "| 数据类型 | 条款 | 风险 | 命中数 | 涉及文件 | 主要字段 |", "|---|---|---|---|---|---|"]
        for k, v in summary.items():
            fields = "、".join(v.get("fields", [])[:4]) or "—"
            L.append(f"| {v['label']} | {v['gdpr_art']} | {SENSITIVITY_CN.get(v['sensitivity'], v['sensitivity'])} | "
                     f"{v['count']} | {v['file_count']} | {fields} |")
        L.append("")

    # ---- 差距项 ----
    failed = [r for r in a.results if r["status"] in (FAIL, PARTIAL)]
    L += [f"## 3. 差距项（共 {len(failed)} 项）", ""]
    if not failed:
        L.append("当前输入下未发现明确差距项。建议定期复核并保留证据。")
    else:
        for sev in ("P0", "P1", "P2"):
            items = [r for r in failed if r["severity"] == sev]
            if not items:
                continue
            L += [f"### {SEVERITY_LABEL[sev]}（{len(items)} 项）", "",
                  "| # | 检查项 | 条款 | 现状 | 整改措施 |", "|---|---|---|---|---|"]
            status_cn = {"fail": "不符合", "partial": "部分符合"}
            for i, r in enumerate(items, 1):
                L.append(f"| {i} | {r['title']} | {r['article']} | {status_cn[r['status']]} | {r['remediation']} |")
            L.append("")

    # ---- 通过项 ----
    passed = [r for r in a.results if r["status"] == PASS]
    if passed:
        L += ["## 4. 已符合项", ""]
        L += [f"- {r['title']}（{r['article']}）" for r in passed]
        L.append("")

    # ---- 时限与罚则 ----
    L += ["## 5. 关键时限", "", "| 事项 | 时限 | 条款 |", "|---|---|---|"]
    L += [f"| {a} | {b} | {c} |" for a, b, c in DEADLINES]
    L += ["", "## 6. 处罚上限（Art.83）", "", "| 上限 | 适用情形 |", "|---|---|"]
    L += [f"| {a} | {b} |" for a, b in FINE_TIERS]

    # 英国经 DUAA 2025 已与欧盟实质分叉，涉及 UK 时必须单独提示
    if str(get(ctx, "jurisdiction", "eu")).lower() in {"uk", "both"}:
        L += ["", "## 7. 英国 GDPR 专项提示（DUAA 2025）", "",
              "英国 Data (Use and Access) Act 2025 于 2025-06-19 获御准，"
              "英国 GDPR 已与欧盟 GDPR 实质分叉，**不能直接套用欧盟结论**：", "",
              "| 维度 | 欧盟 GDPR | 英国 GDPR（DUAA 2025 后） |", "|---|---|---|",
              "| 正当利益 | 必须做三步 LIA 平衡测试 | 新增 Recognised Legitimate Interests 法定清单"
              "（国家安全、犯罪预防、弱势群体保护、紧急情况、民主参与、公共利益），**免做平衡测试** |",
              "| 跨境传输标准 | essentially equivalent（实质等同） | "
              "**not materially lower**（不低于实质水平），风险基准更灵活 |",
              "| DPO | Art.37 强制情形 | 引入 **Senior Responsible Individual (SRI)**，"
              "对部分组织修改或取代强制 DPO 要求 |",
              "| 自动化决策 | Art.22，保障较具体 | 保留同等义务，但触发条件不如欧盟具体 |",
              "| ePrivacy | 成员国国内法 | **PECR，经 DUAA 2025 修订** |",
              "", "> 涉及英国主体时，以上维度需单独做英国专项分析。"
              "详细条文与进展见 `references/updates-2026.md`。"]

    L += ["", "---", "",
          "> 本报告为自动化辅助评估，不构成法律意见。"
          "涉及高风险处理、跨境传输或监管调查时，请咨询数据保护法律顾问。"
          "时效性内容以 `references/updates-2026.md` 为准。"]

    return "\n".join(L)


def render_ropa(a: Assessment) -> str:
    ctx, scan = a.context, a.scan
    summary = scan.get("summary", {})
    cats = "、".join(v["label"] for v in summary.values()) or "（待补充）"
    subjects = "、".join(v["label"] for v in summary.values()) or "（待补充）"

    L = [
        "# 处理活动记录（ROPA）— Art.30",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        "| Art.30 要求项 | 内容 | 状态 |",
        "|---|---|---|",
        f"| (a) 控制者名称与联系方式 | {get(ctx, 'controller.name') or '待补充'} / "
        f"{get(ctx, 'controller.contact') or '待补充'} | {'已填' if get(ctx, 'controller.name') else '待补充'} |",
        f"| (a) 联合控制者 / 代表 / DPO | 代表: {'是' if get(ctx, 'controller.eu_representative') else '否'}；"
        f"DPO: {'是' if get(ctx, 'controller.dpo') else '否'} | 待核实 |",
        f"| (b) 处理目的 | {get(ctx, 'processing.purpose') or '待补充'} | "
        f"{'已填' if get(ctx, 'processing.purpose') else '待补充'} |",
        f"| (c) 数据主体类别与数据类别 | 数据类别：{cats} | 待补充主体类别 |",
        f"| (d) 接收方类别 | {'第三方处理者' if get(ctx, 'third_parties.shared') else '无'} | 待补充 |",
        f"| (e) 第三国传输与保障措施 | {get(ctx, 'cross_border.mechanism', 'none')}"
        f"{'/' + '、'.join(get(ctx, 'cross_border.countries', []) or []) if get(ctx, 'cross_border.enabled') else ''} | 待核实 |",
        f"| (f)  envisaged 留存期限 | {get(ctx, 'retention.days') or '未定义'} 天 | "
        f"{'已定义' if get(ctx, 'retention.defined') else '待补充'} |",
        f"| (g) 技术与组织安全措施 | 传输加密: {'是' if get(ctx, 'security.encryption_in_transit') else '否'}；"
        f"静态加密: {'是' if get(ctx, 'security.encryption_at_rest') else '否'}；"
        f"访问控制: {'是' if get(ctx, 'security.access_control') else '否'} | 待核实 |",
        "",
        "## 待人工补充项",
        "",
        "1. 数据主体类别（如：注册用户、员工、客户联系人、网站访客）",
        "2. 各类数据的具体留存起算点与到期处置方式",
        "3. 接收方完整清单及其所在地",
        "4. 跨境传输的 TIA 结论与补充措施",
        "5. 安全措施的技术实现细节与测试记录",
        "",
        f"> 数据类别自动提取自扫描结果：{subjects}",
    ]
    return "\n".join(L)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(description="GDPR 合规差距评估：生成差距报告与 ROPA 草稿。")
    p.add_argument("--scan", help="scan_data.py 输出的 JSON 文件")
    p.add_argument("--context", help="处理上下文 JSON 文件")
    p.add_argument("--interactive", action="store_true", help="终端问答方式收集上下文")
    p.add_argument("--init-context", dest="init_context", help="生成上下文模板到指定路径")
    p.add_argument("--out", help="输出 Markdown 差距报告路径")
    p.add_argument("--ropa", help="输出 ROPA 草稿路径")
    args = p.parse_args(argv)

    if args.init_context:
        Path(args.init_context).write_text(
            json.dumps(CONTEXT_TEMPLATE, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"[已生成] 上下文模板 → {args.init_context}")
        print("填写后再运行：assess.py --scan scan.json --context context.json --out report.md")
        return 0

    scan_data: dict = {}
    if args.scan:
        sp = Path(args.scan)
        if not sp.exists():
            print(f"[错误] 扫描结果文件不存在: {sp}", file=sys.stderr)
            return 2
        scan_data = json.loads(sp.read_text(encoding="utf-8"))

    if args.context:
        cp = Path(args.context)
        if not cp.exists():
            print(f"[错误] 上下文文件不存在: {cp}", file=sys.stderr)
            return 2
        ctx = deep_merge(CONTEXT_TEMPLATE, json.loads(cp.read_text(encoding="utf-8")))
    elif args.interactive:
        ctx = interactive_context(scan_data.get("summary", {}))
    else:
        print("[错误] 需要 --context 或 --interactive，或用 --init-context 生成模板。", file=sys.stderr)
        return 2

    a = Assessment(context=ctx, scan=scan_data)
    for chk in CHECKS:
        try:
            status = chk.verify(ctx, scan_data.get("summary", {}))
        except Exception as exc:  # 单项失败不应中断整份报告
            status = FAIL
            print(f"[警告] 检查项 {chk.id} 执行异常: {exc}", file=sys.stderr)
        a.results.append({
            "id": chk.id, "dimension": chk.dimension, "article": chk.article,
            "title": chk.title, "severity": chk.severity,
            "status": status, "remediation": chk.remediation,
        })

    report = render_report(a)
    if args.out:
        Path(args.out).write_text(report, encoding="utf-8")
        print(f"[已写入] 差距报告 → {args.out}")
    else:
        print(report)

    if args.ropa:
        Path(args.ropa).write_text(render_ropa(a), encoding="utf-8")
        print(f"[已写入] ROPA 草稿 → {args.ropa}")

    print(f"\n综合评分：{a.overall()} / 100 —— {a.grade()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
