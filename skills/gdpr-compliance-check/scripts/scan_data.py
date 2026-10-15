#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDPR PII Scanner — 扫描数据文件，识别受 GDPR 管辖的个人数据并给出风险分级。

设计原则：
1. 结构优先 —— CSV/JSON 先看字段名，再看值。字段名的信号比正则强得多。
2. 值正则兜底 —— 日志 / SQL / 纯文本没有字段结构，只能扫值。
3. 样例一律脱敏 —— 报告里绝不落明文个人数据（报告本身也会变成待管数据）。
4. 只依赖标准库 —— xlsx/parquet 走可选导入，装了就扫，没装就跳过并提示。

用法：
    python3 scan_data.py <path>                       # 扫描文件/目录，输出终端摘要
    python3 scan_data.py <path> --json out.json       # 输出结构化结果，供 assess.py 消费
    python3 scan_data.py <path> --md report.md        # 输出 Markdown 报告
    python3 scan_data.py <path> --max-rows 5000       # 提高每文件采样行数
    python3 scan_data.py <path> --redact              # 连脱敏样例都不输出（最高安全级）

退出码：0 未发现 / 1 发现个人数据 / 2 用法或运行错误
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field as dc_field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

# --------------------------------------------------------------------------- #
# 基础配置
# --------------------------------------------------------------------------- #

MAX_BYTES_DEFAULT = 25 * 1024 * 1024   # 单文件超过 25MB 默认跳过内容扫描
MAX_ROWS_DEFAULT = 2000                # 每文件默认采样行数
SAMPLE_VALUES_PER_COLUMN = 25          # 每列抽取多少个非空值做正则判定
HIT_RATE_THRESHOLD = 0.6               # 值正则命中率高于此值才判定该列属于该类型

TEXT_EXT = {
    ".csv", ".tsv", ".txt", ".md", ".log", ".sql", ".json", ".jsonl", ".ndjson",
    ".xml", ".yaml", ".yml", ".ini", ".cfg", ".env", ".rtf",
}
STRUCT_EXT = {".csv", ".tsv", ".json", ".jsonl", ".ndjson"}
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".next", ".idea", ".vscode", "site-packages", "vendor", ".cache", "coverage",
}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}

# --------------------------------------------------------------------------- #
# 个人数据类型定义
#   gdpr_art : 关联条款；sensitivity: critical / high / medium / low
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class PIIType:
    key: str
    label: str
    gdpr_art: str
    sensitivity: str
    note: str


PII_TYPES: dict[str, PIIType] = {t.key: t for t in [
    # ---- 直接标识符 ----
    PIIType("email", "邮箱地址", "Art.4(1)", "medium",
            "单独即可或结合其他信息识别自然人；营销用途还需遵守 ePrivacy 指令"),
    PIIType("phone", "电话号码", "Art.4(1)", "high",
            "号码通常可直接联系到本人，泄露后骚扰风险高"),
    PIIType("national_id", "身份证/国民注册号", "Art.4(1)/Art.87", "critical",
            "成员国可就国民识别号码附加条件；建议改用内部替代 ID"),
    PIIType("passport", "护照号", "Art.87", "critical", "旅行证件号，属高敏感标识"),
    PIIType("ssn", "社保号/税号", "Art.4(1)", "critical", "政府颁发的唯一编号"),
    PIIType("name", "姓名", "Art.4(1)", "low",
            "最常见标识符，通常需与其他数据结合才构成高隐私风险"),
    PIIType("address", "居住地址", "Art.4(1)", "high", "可定位到具体住所"),
    PIIType("dob", "出生日期", "Art.4(1)", "medium", "与姓名组合后识别力显著上升"),
    PIIType("gps", "精确位置坐标", "Art.4(1)", "high", "可还原行动轨迹"),
    PIIType("ip", "IP 地址", "Art.4(1)", "medium",
            "CJEU Breyer 案(C-582/14)确认：对控制者而言 IP 属个人数据"),
    PIIType("device_id", "设备/广告标识符", "Art.4(1)", "medium",
            "IDFA/AAID/Cookie ID 等，配合 ePrivacy 需事前同意"),
    PIIType("mac", "MAC 地址", "Art.4(1)", "medium", "网络设备唯一标识"),
    PIIType("uuid", "UUID/会话标识", "Art.4(1)", "low", "若可与账号关联则升级为标识符"),
    PIIType("biometric_id", "生物识别特征", "Art.9(1)", "critical",
            "用于唯一识别即属特殊类别数据，原则禁止处理"),

    # ---- 金融 ----
    PIIType("credit_card", "支付卡号", "Art.4(1)", "critical",
            "建议改用 PSP 令牌化；明文存储卡号同时违反 PCI DSS"),
    PIIType("iban", "银行账户(IBAN)", "Art.4(1)", "critical", "可直接发起扣款"),

    # ---- Art.9 特殊类别 ----
    PIIType("special_health", "健康/医疗数据", "Art.9(1)", "critical",
            "原则禁止，需 Art.9(2) 例外事由（如明示同意、医疗目的）"),
    PIIType("special_religion", "宗教信仰", "Art.9(1)", "critical", "特殊类别数据"),
    PIIType("special_politics", "政治观点/工会成员", "Art.9(1)", "critical", "特殊类别数据"),
    PIIType("special_sexual", "性生活/性取向", "Art.9(1)", "critical", "特殊类别数据"),
    PIIType("special_race", "种族/民族出身", "Art.9(1)", "critical", "特殊类别数据"),
    PIIType("special_genetic", "基因数据", "Art.9(1)", "critical", "特殊类别数据"),
    PIIType("criminal", "犯罪记录/定罪数据", "Art.10", "critical",
            "仅在官方授权或法律授权下处理"),

    # ---- 其他 ----
    PIIType("credential", "凭据/密钥", "Art.32", "critical",
            "口令/API Key 明文入库既违反安全义务，也放大泄露后果"),
    PIIType("minor", "未成年人(<16)个人信息", "Art.8", "high",
            "信息社会服务需监护人同意；成员国可将年龄下限下调至 13"),
]}

SENSITIVITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SENSITIVITY_CN = {"critical": "极高", "high": "高", "medium": "中", "low": "低"}


# --------------------------------------------------------------------------- #
# 字段名词表（中英双语）—— 结构模式的主要依据
# --------------------------------------------------------------------------- #

FIELD_VOCAB: dict[str, list[str]] = {
    "email": ["email", "e-mail", "mail", "邮箱", "邮件", "电子邮箱", "emailaddress",
              "contact_email", "user_email", "login_email"],
    "phone": ["phone", "mobile", "tel", "telephone", "cellphone", "msisdn", "contact",
              "手机", "电话", "手机号", "联系电话", "联系方式", "mobile_no", "phone_number"],
    "national_id": ["id_card", "idcard", "id_number", "national_id", "identity", "ssn_no",
                    "nin", "nino", "codice_fiscale", "nif", "bsn", "personnummer",
                    "身份证", "身份证号", "证件号", "证件号码", "国民身份"],
    "passport": ["passport", "passport_no", "passport_number", "护照", "护照号"],
    "ssn": ["ssn", "social_security", "tax_id", "taxid", "tin", "steuer_id",
            "社保号", "社会保障号", "税号", "纳税人识别号"],
    "name": ["name", "full_name", "fullname", "first_name", "firstname", "last_name",
             "lastname", "surname", "given_name", "family_name", "username",
             "contact_name", "姓名", "名字", "用户名", "真实姓名", "昵称", "nickname"],
    "address": ["address", "addr", "street", "home_address", "billing_address",
                "shipping_address", "postcode", "postal_code", "zip", "zipcode",
                "地址", "住址", "家庭住址", "收货地址", "邮编", "邮政编码"],
    "dob": ["birth", "birthday", "birth_date", "dob", "date_of_birth", "born",
            "出生", "生日", "出生日期", "出生年月"],
    "gps": ["lat", "latitude", "lng", "lon", "long", "longitude", "gps", "geo",
            "coordinate", "coords", "location", "经度", "纬度", "坐标", "定位"],
    "ip": ["ip", "ip_address", "ipaddr", "client_ip", "remote_addr", "x_forwarded_for",
           "ipv4", "ipv6", "ip地址", "客户端ip"],
    "device_id": ["device_id", "deviceid", "idfa", "aaid", "gaid", "advertising_id",
                  "adid", "android_id", "imei", "cookie_id", "fingerprint",
                  "设备号", "设备标识", "广告标识"],
    "mac": ["mac", "mac_address", "mac地址", "物理地址"],
    "uuid": ["uuid", "guid", "session_id", "sessionid", "visitor_id", "request_id"],
    "biometric_id": ["face", "facial", "faceprint", "fingerprint_bio", "iris", "voiceprint",
                     "人脸", "指纹", "虹膜", "声纹", "面部特征"],
    "credit_card": ["card_no", "card_number", "cardno", "credit_card", "pan", "cvv", "cvc",
                    "卡号", "银行卡", "信用卡"],
    "iban": ["iban", "bank_account", "account_no", "account_number", "银行账号", "银行卡号"],
    "special_health": ["health", "medical", "diagnosis", "patient", "disease", "symptom",
                       "disability", "blood_type", "allergy", "健康", "医疗", "病历",
                       "诊断", "疾病", "症状", "残疾", "血型", "过敏"],
    "special_religion": ["religion", "religious", "faith", "church", "宗教", "信仰"],
    "special_politics": ["political", "politics", "party", "union", "trade_union",
                         "政治", "党派", "工会"],
    "special_sexual": ["sexual", "sexuality", "sex_orientation", "lgbt", "gender_identity",
                       "性取向", "性生活"],
    "special_race": ["race", "racial", "ethnic", "ethnicity", "种族", "民族", "族裔"],
    "special_genetic": ["genetic", "dna", "genome", "基因", "遗传"],
    "criminal": ["criminal", "conviction", "offense", "criminal_record", "犯罪", "定罪", "案底"],
    "credential": ["password", "passwd", "pwd", "secret", "api_key", "apikey",
                   "access_token", "token", "private_key", "密码", "口令", "密钥"],
    "minor": ["age", "grade", "school", "guardian", "parent", "年龄", "年级", "学校",
              "监护人", "家长"],
}

# 编译后的字段名匹配器：整词匹配优先，避免 "mail" 命中 "email_addr" 之外的误报
FIELD_PATTERNS: dict[str, list[re.Pattern]] = {}
for _key, _words in FIELD_VOCAB.items():
    _pats = []
    for _w in _words:
        if not _w:
            continue
        # 拉丁词：按非字母数字边界整词匹配
        if re.fullmatch(r"[a-zA-Z_0-9]+", _w):
            _pats.append(re.compile(r"(?<![a-z0-9])" + re.escape(_w) + r"(?![a-z0-9])", re.I))
        else:
            _pats.append(re.compile(re.escape(_w), re.I))
    FIELD_PATTERNS[_key] = _pats


# --------------------------------------------------------------------------- #
# 值正则
# --------------------------------------------------------------------- #

RE_EMAIL = re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}\b")
RE_CN_MOBILE = re.compile(r"(?<!\d)(?:\+?86[-\s]?)?1[3-9]\d{9}(?!\d)")
RE_INTL_PHONE = re.compile(r"(?<![\d+])\+\d{1,3}[\s.-]?(?:\(?\d{1,4}\)?[\s.-]?)?\d{2,4}[\s.-]?\d{2,4}(?:[\s.-]?\d{1,4})?(?![\d-])")
RE_CN_ID = re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)")
RE_IPV4 = re.compile(r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?![\d.])")
RE_IPV6 = re.compile(r"(?<![:\w])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}(?![:.\w])")
RE_MAC = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])")
RE_UUID = re.compile(r"(?<![0-9a-zA-Z])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}(?![0-9a-zA-Z])")
RE_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}(?!\d)")
RE_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?![A-Z0-9])")
RE_GPS_PAIR = re.compile(r"[-+]?(?:[1-8]?\d(?:\.\d{3,})|90(?:\.0+)?)\s*[,，]\s*[-+]?(?:\d{1,2}(?:\.\d{3,})|1[0-7]\d(?:\.\d{3,})|180(?:\.0+)?)")
RE_DOB = re.compile(r"(?<!\d)(?:19|20)\d{2}[-/年.]\s?(?:0?[1-9]|1[0-2])[-/月.]\s?(?:0?[1-9]|[12]\d|3[01])日?(?!\d)")
RE_CN_NAME = re.compile(r"(?<![一-龥])(?:赵|钱|孙|李|周|吴|郑|王|冯|陈|褚|卫|蒋|沈|韩|杨|朱|秦|尤|许|何|吕|施|张|孔|曹|严|华|金|魏|陶|姜|戚|谢|邹|喻|柏|水|窦|章|云|苏|潘|葛|奚|范|彭|郎|鲁|韦|昌|马|苗|凤|花|方|俞|任|袁|柳|唐|罗|薛|伍|余|米|贝|姚|孟|顾|尹|江|钟|徐|邱|骆|高|夏|蔡|田|樊|胡|凌|霍|虞|万|支|柯|管|卢|莫|房|缪|丁|贾|路|林|刁|郁|梅|盛|林|刀|黄|穆|萧|尹|姚|邵|湛|汪|祁|毛|禹|狄|贝|明|臧|计|伏|成|戴|谈|宋|茅|庞|熊|纪|舒|屈|项|祝|董|梁|杜|阮|蓝|闽|席|季|麻|强|贾|路|娄|危)[\u4e00-\u9fa5]{1,2}(?![一-龥])")
RE_ADDRESS_CN = re.compile(r"[\u4e00-\u9fa5]{2,}(?:省|市|区|县|镇|街道|路|街|号|栋|单元|室|楼|村)")
RE_POSTCODE = re.compile(r"(?<!\d)(?:\d{5}(?!\d)|\d{6}(?!\d))(?=.*?(?:zip|post|邮编))", re.I)

# Art.9 / Art.10 关键词（值层面，用于日志/自由文本）
SPECIAL_KEYWORDS: dict[str, list[str]] = {
    "special_health": ["diagnos", "patient", "medical record", "blood type", "hiv", "cancer",
                       "pregnan", "disabilit", "病历", "诊断", "病史", "血型", "怀孕", "残疾", "过敏"],
    "special_religion": ["religio", "muslim", "christian", "catholic", "buddhis", "hindu",
                         "jewish", "宗教", "基督", "穆斯林", "佛教", "天主"],
    "special_politics": ["political party", "trade union", "communist", "democrat", "republican",
                         "党派", "工会", "政治倾向"],
    "special_sexual": ["sexual orientation", "gay", "lesbian", "homosexual", "lgbt",
                       "性取向", "同性"],
    "special_race": ["ethnic", "race", "racial", "民族", "种族", "族裔"],
    "special_genetic": ["genetic", "dna sequence", "genome", "基因", "遗传"],
    "criminal": ["criminal record", "convict", "arrest", "犯罪记录", "前科", "案底"],
}


# --------------------------------------------------------------------------- #
# 校验算法
# --------------------------------------------------------------------------- #

def luhn_ok(digits: str) -> bool:
    """Luhn 校验，用于剔除卡号正则的误报。"""
    d = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(d) <= 19:
        return False
    total, parity = 0, len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    """IBAN mod-97 校验。"""
    s = re.sub(r"\s+", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    rearranged = s[4:] + s[:4]
    try:
        numeric = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


_CN_ID_WEIGHTS = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
_CN_ID_CHECK = "10X98765432"


def cn_id_ok(value: str) -> bool:
    """中国大陆 18 位身份证校验位验证。"""
    s = value.upper()
    if len(s) != 18 or not re.fullmatch(r"\d{17}[\dX]", s):
        return False
    try:
        total = sum(int(s[i]) * _CN_ID_WEIGHTS[i] for i in range(17))
    except ValueError:
        return False
    return _CN_ID_CHECK[total % 11] == s[17]


def valid_date_like(value: str) -> bool:
    """宽松判定：值里含 1900-2100 年份且看起来像日期。"""
    m = re.search(r"(19|20)\d{2}", value)
    return bool(m)


# --------------------------------------------------------------------------- #
# 脱敏
# --------------------------------------------------------------------------- #

def mask_email(v: str) -> str:
    try:
        local, domain = v.rsplit("@", 1)
    except ValueError:
        return "***"
    head = local[:1] if len(local) <= 2 else local[:2]
    return f"{head}***@{domain}"


def mask_keep_edges(v: str, keep: int = 2) -> str:
    s = re.sub(r"\s+", "", v)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * (len(s) - keep * 2)}{s[-keep:]}"


def mask_generic(v: str) -> str:
    s = str(v).strip()
    if "@" in s:
        return mask_email(s)
    if len(s) > 40:
        s = s[:40] + "…"
    return mask_keep_edges(s)


def mask_by_type(key: str, v: str) -> str:
    if key == "email":
        return mask_email(v)
    if key == "ip":
        parts = v.split(".")
        return f"{parts[0]}.*.*.{parts[-1]}" if len(parts) == 4 else mask_keep_edges(v, 3)
    if key == "gps":
        # 坐标降到 ~1km 精度，避免把精确位置写进报告
        nums = re.findall(r"[-+]?\d+(?:\.\d+)?", v)
        if len(nums) >= 2:
            return f"{float(nums[0]):.1f}, {float(nums[1]):.1f} (已降精度)"
        return "***"
    if key == "dob":
        m = re.search(r"((?:19|20)\d{2})", v)
        return f"{m.group(1)}-**-**" if m else "***"
    return mask_generic(v)


# --------------------------------------------------------------------------- #
# 数据结构
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    pii_type: str
    source: str            # "field" 字段结构 | "value" 值正则 | "keyword" 特殊类别关键词
    location: str          # 文件相对路径
    field: Optional[str] = None
    count: int = 0
    samples: list[str] = dc_field(default_factory=list)
    line: Optional[int] = None

    @property
    def meta(self) -> PIIType:
        return PII_TYPES[self.pii_type]


@dataclass
class ScanResult:
    root: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list[Finding] = dc_field(default_factory=list)
    skipped: list[dict[str, str]] = dc_field(default_factory=list)

    # ---- 聚合视图 ----
    def by_type(self) -> dict[str, dict[str, Any]]:
        agg: dict[str, dict[str, Any]] = {}
        for f in self.findings:
            a = agg.setdefault(f.pii_type, {"count": 0, "files": set(), "fields": set()})
            a["count"] += f.count
            a["files"].add(f.location)
            if f.field:
                a["fields"].add(f.field)
        for a in agg.values():
            a["files"] = sorted(a["files"])
            a["fields"] = sorted(a["fields"])[:20]
        return agg

    def max_sensitivity(self) -> Optional[str]:
        if not self.findings:
            return None
        return max((f.meta.sensitivity for f in self.findings),
                   key=lambda s: SENSITIVITY_ORDER[s])

    def to_dict(self, redact: bool = False) -> dict[str, Any]:
        return {
            "tool": "gdpr-scan",
            "version": "1.0",
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "root": self.root,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "max_sensitivity": self.max_sensitivity(),
            "summary": {
                k: {
                    "label": PII_TYPES[k].label,
                    "gdpr_art": PII_TYPES[k].gdpr_art,
                    "sensitivity": PII_TYPES[k].sensitivity,
                    "count": v["count"],
                    "file_count": len(v["files"]),
                    "fields": v["fields"],
                    "files": v["files"],
                }
                for k, v in sorted(
                    self.by_type().items(),
                    key=lambda kv: (-SENSITIVITY_ORDER[PII_TYPES[kv[0]].sensitivity], -kv[1]["count"]),
                )
            },
            "findings": [
                {
                    "type": f.pii_type,
                    "label": f.meta.label,
                    "gdpr_art": f.meta.gdpr_art,
                    "sensitivity": f.meta.sensitivity,
                    "source": f.source,
                    "file": f.location,
                    "field": f.field,
                    "line": f.line,
                    "count": f.count,
                    "samples": [] if redact else f.samples,
                }
                for f in self.findings
            ],
            "skipped_files": self.skipped,
        }


# --------------------------------------------------------------------------- #
# 值检测：给定字符串，返回命中的 PII 类型集合
# --------------------------------------------------------------------------- #

def detect_value(text: str) -> list[tuple[str, str]]:
    """返回 [(pii_type, matched_value), ...]。"""
    hits: list[tuple[str, str]] = []
    s = str(text)
    if not s or len(s) > 500:
        return hits

    for m in RE_EMAIL.finditer(s):
        hits.append(("email", m.group(0)))
    for m in RE_CN_ID.finditer(s):
        if cn_id_ok(m.group(0)):
            hits.append(("national_id", m.group(0)))
    for m in RE_IBAN.finditer(s):
        if iban_ok(m.group(0)):
            hits.append(("iban", m.group(0)))
    for m in RE_CARD.finditer(s):
        raw = m.group(0)
        digits = re.sub(r"[ -]", "", raw)
        if luhn_ok(digits) and not RE_IBAN.fullmatch(raw.upper()):
            hits.append(("credit_card", raw))
    for m in RE_MAC.finditer(s):
        hits.append(("mac", m.group(0)))
    for m in RE_IPV6.finditer(s):
        hits.append(("ip", m.group(0)))
    for m in RE_IPV4.finditer(s):
        hits.append(("ip", m.group(0)))
    for m in RE_GPS_PAIR.finditer(s):
        hits.append(("gps", m.group(0)))
    for m in RE_CN_MOBILE.finditer(s):
        hits.append(("phone", m.group(0)))
    for m in RE_INTL_PHONE.finditer(s):
        hits.append(("phone", m.group(0)))
    for m in RE_DOB.finditer(s):
        hits.append(("dob", m.group(0)))
    for m in RE_ADDRESS_CN.finditer(s):
        hits.append(("address", m.group(0)))
    for m in RE_CN_NAME.finditer(s):
        hits.append(("name", m.group(0)))
    for m in RE_UUID.finditer(s):
        hits.append(("uuid", m.group(0)))

    lower = s.lower()
    for key, words in SPECIAL_KEYWORDS.items():
        for w in words:
            if w in lower:
                hits.append((key, w))
                break
    return hits


def detect_field(field_name: str) -> list[str]:
    """根据字段名返回可能的 PII 类型。"""
    out = []
    for key, pats in FIELD_PATTERNS.items():
        for p in pats:
            if p.search(field_name):
                out.append(key)
                break
    return out


# 列级判定中「不能只靠值正则」的类型：日期格式过于常见，
# 仅凭值会把 ts / created_at 之类的时间戳误判成出生日期。
FIELD_ONLY_TYPES = {"dob", "name", "minor"}


def detect_minors(values: list[str], threshold: int = 16) -> tuple[int, int, Optional[str]]:
    """从出生日期样本推算未成年人数量（按年份近似）。返回 (未成年数, 可解析数, 样例)。"""
    under = total = 0
    sample: Optional[str] = None
    year_now = datetime.now().year
    for v in values:
        m = re.search(r"(?:19|20)(\d{2})", str(v))
        if not m:
            continue
        total += 1
        if year_now - int(m.group(1)) < threshold:
            under += 1
            sample = sample or str(v)
    return under, total, sample


def judge_column(location: str, col_label: str, values: list[str], redact: bool) -> list[Finding]:
    """
    判定一列数据是否含个人数据 —— scan_csv / scan_json / scan_xlsx 共用的核心逻辑。

    优先级：
      1. 字段名命中词表 → 直接判定（信号最强）
      2. 否则用值正则：普通类型要求命中率 ≥ 60%；
         Art.9/Art.10 特殊类别只要命中 1 次就报（宁可误报，不可漏报）
    """
    findings: list[Finding] = []

    field_types = detect_field(col_label)
    if field_types:
        for t in field_types:
            findings.append(Finding(
                pii_type=t, source="field", location=location, field=col_label,
                count=len(values),
                samples=[] if redact else [mask_by_type(t, values[0])],
            ))
        if "dob" in field_types:
            under, total, sample = detect_minors(values)
            if under and total:
                findings.append(Finding(
                    pii_type="minor", source="field", location=location,
                    field=f"{col_label}(推算<16岁)", count=under,
                    samples=[] if redact else [mask_by_type("dob", sample or "")],
                ))
        return findings

    counter: Counter = Counter()
    examples: dict[str, str] = {}
    for v in values:
        for t, matched in detect_value(v):
            if t in FIELD_ONLY_TYPES:
                continue
            counter[t] += 1
            examples.setdefault(t, matched)

    for t, c in counter.items():
        if t in SPECIAL_KEYWORDS or t == "criminal":
            need = 1                      # 敏感类别：命中即报，交人工复核
        else:
            need = max(1, int(len(values) * HIT_RATE_THRESHOLD))
        if c >= need:
            findings.append(Finding(
                pii_type=t,
                source="keyword" if (t in SPECIAL_KEYWORDS or t == "criminal") else "value",
                location=location, field=col_label, count=c,
                samples=[] if redact else [mask_by_type(t, examples[t])],
            ))
    return findings


# --------------------------------------------------------------------------- #
# 文件读取
# --------------------------------------------------------------------------- #

def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")]
        for fn in filenames:
            if fn in SKIP_FILES:
                continue
            p = Path(dirpath) / fn
            if p.suffix.lower() in TEXT_EXT or p.suffix.lower() in {".xlsx", ".xls", ".parquet"}:
                yield p


def read_text(path: Path, max_bytes: int) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
    except OSError:
        return None
    for enc in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return path.read_text(encoding=enc, errors="replace")
        except (UnicodeDecodeError, OSError):
            continue
    return None


# --------------------------------------------------------------------------- #
# 各类格式的扫描器
# --------------------------------------------------------------------------- #

def scan_csv(path: Path, rel: str, text: str, max_rows: int, redact: bool) -> list[Finding]:
    delim = "\t" if path.suffix.lower() == ".tsv" else ","
    findings: list[Finding] = []
    try:
        reader = csv.DictReader(io.StringIO(text), delimiter=delim)
        if not reader.fieldnames:
            return findings
    except csv.Error:
        return findings

    col_values: dict[str, list[str]] = defaultdict(list)
    rows = 0
    for row in reader:
        rows += 1
        if rows > max_rows:
            break
        for k, v in row.items():
            if k is None:
                continue
            v = (v or "").strip()
            if v and len(col_values[k]) < SAMPLE_VALUES_PER_COLUMN:
                col_values[k].append(v)

    for col, values in col_values.items():
        if not col.strip():
            continue
        findings.extend(judge_column(rel, col, values, redact))
    return findings


def walk_json(obj: Any, path: str = "", depth: int = 0, out: Optional[dict] = None) -> dict:
    """把嵌套 JSON 摊平成 {扁平键路径: 值列表}。"""
    if out is None:
        out = defaultdict(list)
    if depth > 6:
        return out
    if isinstance(obj, dict):
        for k, v in obj.items():
            walk_json(v, f"{path}.{k}" if path else str(k), depth + 1, out)
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:200]):
            walk_json(v, f"{path}[]", depth + 1, out)
    else:
        if obj is not None and str(obj).strip():
            if len(out[path]) < SAMPLE_VALUES_PER_COLUMN:
                out[path].append(str(obj))
    return out


def scan_json(path: Path, rel: str, text: str, redact: bool) -> list[Finding]:
    findings: list[Finding] = []
    suffix = path.suffix.lower()

    if suffix in {".jsonl", ".ndjson"}:
        records = [ln for ln in text.splitlines() if ln.strip()][:MAX_ROWS_DEFAULT]
        flat: dict[str, list[str]] = defaultdict(list)
        for ln in records:
            try:
                walk_json(json.loads(ln), "", 0, flat)
            except json.JSONDecodeError:
                continue
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            # 退化为纯文本扫描
            return scan_text(path, rel, text, MAX_ROWS_DEFAULT, redact)
        flat = walk_json(data)

    for key, values in flat.items():
        leaf = key.split(".")[-1].replace("[]", "")
        # 用叶子键名做字段判定，完整路径保留在报告里便于定位
        for f in judge_column(rel, leaf, values, redact):
            f.field = key
            findings.append(f)
    return findings


def scan_text(path: Path, rel: str, text: str, max_rows: int, redact: bool) -> list[Finding]:
    """逐行扫描值正则，用于日志 / SQL / Markdown 等非结构化文本。"""
    counter: Counter = Counter()
    examples: dict[str, str] = {}
    first_line: dict[str, int] = {}
    for i, line in enumerate(text.splitlines()[:max_rows], start=1):
        if len(line) > 4000:
            line = line[:4000]
        for t, matched in detect_value(line):
            counter[t] += 1
            examples.setdefault(t, matched)
            first_line.setdefault(t, i)

    findings = []
    for t, c in counter.items():
        findings.append(Finding(
            pii_type=t,
            source="keyword" if t in SPECIAL_KEYWORDS else "value",
            location=rel, field=None, count=c, line=first_line.get(t),
            samples=[] if redact else [mask_by_type(t, examples[t])],
        ))
    return findings


def scan_xlsx(path: Path, rel: str, redact: bool) -> list[Finding]:
    try:
        from openpyxl import load_workbook  # type: ignore
    except ImportError:
        return []
    findings: list[Finding] = []
    try:
        wb = load_workbook(path, read_only=True, data_only=True)
    except Exception:
        return findings

    for ws in wb.worksheets:
        rows = ws.iter_rows(max_row=MAX_ROWS_DEFAULT, values_only=True)
        try:
            header = next(rows)
        except StopIteration:
            continue
        header = [str(h) if h is not None else "" for h in header]
        col_values: dict[int, list[str]] = defaultdict(list)
        for r in rows:
            for idx, v in enumerate(r):
                if v is None:
                    continue
                s = str(v).strip()
                if s and len(col_values[idx]) < SAMPLE_VALUES_PER_COLUMN:
                    col_values[idx].append(s)
        for idx, values in col_values.items():
            col = header[idx] if idx < len(header) else f"col_{idx + 1}"
            for f in judge_column(rel, col, values, redact):
                f.field = f"{ws.title}!{col}"
                findings.append(f)
    try:
        wb.close()
    except Exception:
        pass
    return findings


# --------------------------------------------------------------------------- #
# 主扫描流程
# --------------------------------------------------------------------------- #

def scan(root: Path, max_rows: int, max_bytes: int, redact: bool) -> ScanResult:
    result = ScanResult(root=str(root))
    xlsx_missing = False

    for path in iter_files(root):
        rel = str(path if path.is_file() and root.is_file() else path.relative_to(root))
        suffix = path.suffix.lower()

        if suffix in {".xlsx", ".xls"}:
            try:
                from openpyxl import load_workbook  # noqa: F401
            except ImportError:
                xlsx_missing = True
                result.files_skipped += 1
                result.skipped.append({"file": rel, "reason": "需要 openpyxl (pip install openpyxl)"})
                continue
            result.files_scanned += 1
            result.findings.extend(scan_xlsx(path, rel, redact))
            continue

        if suffix == ".parquet":
            result.files_skipped += 1
            result.skipped.append({"file": rel, "reason": "parquet 需 pandas/pyarrow，请先导出为 CSV"})
            continue

        try:
            size = path.stat().st_size
        except OSError:
            continue
        if size > max_bytes:
            result.files_skipped += 1
            result.skipped.append({"file": rel, "reason": f"超过 {max_bytes // 1024 // 1024}MB，跳过内容扫描"})
            continue

        text = read_text(path, max_bytes)
        if text is None:
            result.files_skipped += 1
            result.skipped.append({"file": rel, "reason": "无法以文本方式读取"})
            continue

        result.files_scanned += 1
        if suffix in STRUCT_EXT and suffix != ".tsv":
            if suffix == ".csv":
                result.findings.extend(scan_csv(path, rel, text, max_rows, redact))
            else:
                result.findings.extend(scan_json(path, rel, text, redact))
        elif suffix == ".tsv":
            result.findings.extend(scan_csv(path, rel, text, max_rows, redact))
        else:
            result.findings.extend(scan_text(path, rel, text, max_rows, redact))

    if xlsx_missing:
        print("[提示] 检测到 .xlsx 文件但未安装 openpyxl，已跳过。"
              " 安装后可扫描：`pip install openpyxl`", file=sys.stderr)
    return result


# --------------------------------------------------------------------------- #
# 输出
# --------------------------------------------------------------------------- #

_RISK_ICON = {"critical": "[!]", "high": "[H]", "medium": "[M]", "low": "[L]"}


def print_console(result: ScanResult, show_samples: bool = True) -> None:
    print("=" * 78)
    print("GDPR 个人数据扫描结果")
    print("=" * 78)
    print(f"扫描根路径 : {result.root}")
    print(f"已扫描文件 : {result.files_scanned}   跳过: {result.files_skipped}")
    print()

    if not result.findings:
        print("未发现明显的个人数据字段或值。")
        print("注意：这不等于完全合规 —— 需结合合法性基础、留存期限等维度综合判断（见 assess.py）。")
        return

    summary = result.to_dict()["summary"]
    print(f"{'风险':<4} {'数据类型':<22} {'条款':<12} {'命中数':>7}  {'涉及文件':>6}")
    print("-" * 78)
    for key, v in summary.items():
        icon = _RISK_ICON[v["sensitivity"]]
        print(f"{icon:<4} {v['label']:<22} {v['gdpr_art']:<12} {v['count']:>7}  {v['file_count']:>6}")
    print("-" * 78)

    crit = [k for k, v in summary.items() if v["sensitivity"] == "critical"]
    high = [k for k, v in summary.items() if v["sensitivity"] == "high"]
    minors = "minor" in summary

    print()
    print("关键提示：")
    if crit:
        names = "、".join(summary[k]["label"] for k in crit)
        print(f"  - 发现 Art.9 特殊类别 / 高敏感数据：{names}")
        print("    → 原则禁止处理，必须落到 Art.9(2) 的例外事由上，否则应立即停止处理。")
    if high:
        names = "、".join(summary[k]["label"] for k in high)
        print(f"  - 高敏感数据：{names}")
        print("    → 建议加密存储 + 最小化收集 + 明确留存期限。")
    if minors:
        print("  - 疑似含未成年人数据（Art.8）→ 信息社会服务需取得监护人同意。")
    print("  - 下一步：运行 assess.py 生成完整合规差距报告与 ROPA 草稿。")

    if show_samples:
        print()
        print("样例（已脱敏，仅用于定位字段）：")
        for key, v in list(summary.items())[:12]:
            if v["fields"]:
                print(f"  {v['label']}: {', '.join(v['fields'][:6])}")


def render_markdown(result: ScanResult) -> str:
    d = result.to_dict()
    lines = [
        "# GDPR 个人数据扫描报告",
        "",
        f"- 扫描根路径：`{d['root']}`",
        f"- 生成时间：{d['generated_at']}",
        f"- 已扫描文件：{d['files_scanned']}（跳过 {d['files_skipped']}）",
        "",
        "## 1. 发现汇总",
        "",
        "| 风险等级 | 数据类型 | GDPR 条款 | 命中数 | 涉及文件数 |",
        "|---|---|---|---|---|",
    ]
    for k, v in d["summary"].items():
        lines.append(
            f"| {SENSITIVITY_CN[v['sensitivity']]} | {v['label']} | {v['gdpr_art']} | "
            f"{v['count']} | {v['file_count']} |"
        )

    lines += ["", "## 2. 字段级明细", ""]
    for f in d["findings"]:
        loc = f"{f['file']}" + (f" → `{f['field']}`" if f.get("field") else "")
        lines.append(f"- **{f['label']}**（{f['gdpr_art']}，风险 {SENSITIVITY_CN[f['sensitivity']]}）"
                     f" {loc}，命中 {f['count']} 次"
                     + (f"，样例 `{f['samples'][0]}`" if f.get("samples") else ""))

    if d["skipped_files"]:
        lines += ["", "## 3. 跳过文件", ""]
        for s in d["skipped_files"]:
            lines.append(f"- `{s['file']}` — {s['reason']}")

    lines += ["", "---", "",
              "> 本报告由扫描器自动生成，仅覆盖「数据识别」维度。"
              "合法性基础、留存期限、跨境传输、数据主体权利响应等需结合 assess.py 与人工判断。"]
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(
        description="GDPR 个人数据扫描器：识别文件/目录中的个人数据并给出风险分级。")
    p.add_argument("path", help="待扫描的文件或目录")
    p.add_argument("--json", dest="json_out", help="输出 JSON 结果路径（供 assess.py 消费）")
    p.add_argument("--md", dest="md_out", help="输出 Markdown 报告路径")
    p.add_argument("--max-rows", type=int, default=MAX_ROWS_DEFAULT, help=f"每文件采样行数（默认 {MAX_ROWS_DEFAULT}）")
    p.add_argument("--max-bytes", type=int, default=MAX_BYTES_DEFAULT, help="单文件大小上限（字节）")
    p.add_argument("--redact", action="store_true", help="不输出任何样例，仅保留统计")
    p.add_argument("--quiet", action="store_true", help="只写文件，不打印终端摘要")
    args = p.parse_args(argv)

    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"[错误] 路径不存在: {root}", file=sys.stderr)
        return 2

    try:
        result = scan(root, args.max_rows, args.max_bytes, args.redact)
    except KeyboardInterrupt:
        print("\n[中断] 用户取消扫描。", file=sys.stderr)
        return 2

    if not args.quiet:
        print_console(result, show_samples=not args.redact)

    if args.json_out:
        Path(args.json_out).write_text(
            json.dumps(result.to_dict(redact=args.redact), ensure_ascii=False, indent=2),
            encoding="utf-8")
        if not args.quiet:
            print(f"\n[已写入] JSON  → {args.json_out}")

    if args.md_out:
        Path(args.md_out).write_text(render_markdown(result), encoding="utf-8")
        if not args.quiet:
            print(f"[已写入] Markdown → {args.md_out}")

    return 1 if result.findings else 0


if __name__ == "__main__":
    sys.exit(main())
