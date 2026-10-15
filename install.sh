#!/usr/bin/env bash
#
# ellaskills installer
#
# 用法:
#   ./install.sh                        # 安装全部技能
#   ./install.sh gdpr-compliance-check  # 只装指定技能
#   SKILLS_DIR=/path/to/skills ./install.sh   # 自定义安装目录
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET="${SKILLS_DIR:-$HOME/.workbuddy/skills}"

# 颜色（非 TTY 时自动关闭）
if [ -t 1 ]; then
  GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'; RED=$'\033[0;31m'; RESET=$'\033[0m'
else
  GREEN=""; YELLOW=""; RED=""; RESET=""
fi

log()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$GREEN" "$RESET" "$*"; }
warn() { printf '%s!%s %s\n' "$YELLOW" "$RESET" "$*"; }
err()  { printf '%s✗%s %s\n' "$RED" "$RESET" "$*" >&2; }

# 收集待安装技能
# 注意：刻意避开 mapfile / 数组进程替换，macOS 自带 bash 3.2 不支持
if [ "$#" -eq 0 ]; then
  SKILLS=()
  while IFS= read -r name; do
    [ -n "$name" ] && SKILLS+=("$name")
  done <<EOF
$(cd "$REPO_ROOT/skills" 2>/dev/null && ls -1d */ 2>/dev/null | sed 's#/##' | sort)
EOF
else
  SKILLS=("$@")
fi

if [ "${#SKILLS[@]}" -eq 0 ]; then
  err "没有找到可安装的技能（skills/ 目录为空？）"
  exit 1
fi

log ""
log "ellaskills installer"
log "  源目录 : $REPO_ROOT/skills"
log "  目标   : $TARGET"
log ""

mkdir -p "$TARGET"
INSTALLED=0

for skill in "${SKILLS[@]}"; do
  src="$REPO_ROOT/skills/$skill"
  dst="$TARGET/$skill"

  if [ ! -d "$src" ]; then
    warn "跳过 '$skill' — 源目录不存在"
    continue
  fi

  if [ ! -f "$src/SKILL.md" ]; then
    warn "跳过 '$skill' — 缺少 SKILL.md，不是合法技能"
    continue
  fi

  if [ -d "$dst" ]; then
    warn "'$skill' 已存在，覆盖中..."
    rm -rf "$dst"
  fi

  cp -R "$src" "$dst"
  chmod +x "$dst"/scripts/*.sh 2>/dev/null || true
  chmod +x "$dst"/scripts/*.py 2>/dev/null || true
  ok "已安装 $skill"
  INSTALLED=$((INSTALLED + 1))
done

log ""
if [ "$INSTALLED" -gt 0 ]; then
  ok "完成：$INSTALLED 个技能已安装到 $TARGET"
  log "  重启客户端后生效。"
else
  err "没有安装任何技能"
  exit 1
fi
log ""
