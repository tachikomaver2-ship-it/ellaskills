<div align="center">

# 🛠️ ellaskills

**可复用的 Agent Skills 集合 — 能跑出结果，而不只是告诉 AI 该怎么想**

[中文](#-中文) · [English](#-english) · [安装](#-安装) · [技能列表](#-技能列表)

</div>

---

## 🇨🇳 中文

### 这是什么

`ellaskills` 是我个人维护的 Agent Skill 仓库。每个 skill 都是一套**可执行**的专业工作流，
而不只是一段提示词。

设计上坚持三条：

| 原则 | 含义 |
|---|---|
| ⚡ **可执行优先** | 能写成脚本的判断，就不交给模型猜。结论要能复现、能审计 |
| 📅 **时效性标注** | 法规、价格、版本这类会变的知识，必须写明"最后核实日期"和"现行 vs 拟议" |
| 🎯 **边界清晰** | 说清楚什么时候不该用它，以及产出不能替代什么 |

### 📦 安装

```bash
# 克隆仓库
git clone https://github.com/tachikomaver2-ship-it/ellaskills.git
cd ellaskills

# 安装全部技能
bash install.sh

# 或只装某一个
bash install.sh gdpr-compliance-check
```

默认安装到 `~/.workbuddy/skills/`（WorkBuddy / Claude Code 通用路径）。
装完重启客户端即可生效。

### 🔍 技能列表

| 技能 | 用途 | 核心能力 |
|---|---|---|
| 🔍 [gdpr-compliance-check](skills/gdpr-compliance-check/README.md) | 欧盟 / 英国 GDPR 数据合规检查 | 扫描个人数据 · 生成差距报告 · 校验隐私政策 |

### 🤝 贡献

欢迎提 issue 和 PR。新增 skill 请遵循：

1. 目录放在 `skills/<skill-name>/`
2. 必须有 `SKILL.md`（含 frontmatter）+ `README.md`（给人看）
3. 脚本只依赖标准库，除非在 README 里写明额外依赖
4. 涉及时效性内容的，必须有独立的更新追踪文件

---

## 🇬🇧 English

### What is this

`ellaskills` is a personal collection of Agent Skills. Each skill is an **executable**
professional workflow — not just a prompt.

Three principles guide everything here:

| Principle | Meaning |
|---|---|
| ⚡ **Executable first** | If a judgment can be written as a script, don't leave it to model guesswork. Results must be reproducible and auditable |
| 📅 **Explicit freshness** | Anything time-sensitive (law, pricing, versions) must carry a "last verified" date and separate what's *in force* from what's *proposed* |
| 🎯 **Clear boundaries** | State when *not* to use it, and what the output cannot replace |

### 📦 Install

```bash
git clone https://github.com/tachikomaver2-ship-it/ellaskills.git
cd ellaskills

bash install.sh                       # install all skills
bash install.sh gdpr-compliance-check # or a single one
```

Installs to `~/.workbuddy/skills/` by default. Restart your client afterwards.

### 🔍 Skills

| Skill | Purpose | Highlights |
|---|---|---|
| 🔍 [gdpr-compliance-check](skills/gdpr-compliance-check/README.md) | EU / UK GDPR data compliance check | PII scanning · gap reports · privacy notice validation |

---

## ⚠️ Disclaimer

These skills are engineering aids, not legal or professional advice.
Outputs are evidence and action items — always have a qualified human review
high-stakes decisions.

## 📄 License

MIT © [Ella (Yichen Shen)](https://github.com/tachikomaver2-ship-it)
