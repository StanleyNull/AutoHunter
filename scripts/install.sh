#!/usr/bin/env bash
# ============================================================================
#  AutoHunter 引导安装脚本
#  Powered By StanleyNull
#
#  用法：  bash scripts/install.sh
#  作用：  检查环境 → 交互式采集必填参数 → 生成 .env → 构建并启动容器
# ============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ---------- 颜色 ----------
if [ -t 1 ]; then
  C_RESET="\033[0m"; C_CYAN="\033[36m"; C_GREEN="\033[32m"
  C_YELLOW="\033[33m"; C_RED="\033[31m"; C_BOLD="\033[1m"; C_DIM="\033[2m"
else
  C_RESET=""; C_CYAN=""; C_GREEN=""; C_YELLOW=""; C_RED=""; C_BOLD=""; C_DIM=""
fi

info()  { printf "${C_CYAN}[*]${C_RESET} %s\n" "$1"; }
ok()    { printf "${C_GREEN}[✓]${C_RESET} %s\n" "$1"; }
warn()  { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$1"; }
err()   { printf "${C_RED}[x]${C_RESET} %s\n" "$1" >&2; }

# ---------- 字符画 Banner ----------
banner() {
  printf "${C_CYAN}${C_BOLD}"
  cat <<'BANNER'

    _         _        _   _             _
   / \  _   _| |_ ___ | | | |_   _ _ __ | |_ ___ _ __
  / _ \| | | | __/ _ \| |_| | | | | '_ \| __/ _ \ '__|
 / ___ \ |_| | || (_) |  _  | |_| | | | | ||  __/ |
/_/   \_\__,_|\__\___/|_| |_|\__,_|_| |_|\__\___|_|

         AI 自主漏洞挖掘平台  ·  Autonomous Bug Hunter
                    >>  锁定 · 侦察 · 出洞  <<
BANNER
  printf "${C_RESET}"
  printf "${C_DIM}        Powered By StanleyNull${C_RESET}\n\n"
}

# ---------- 环境检查 ----------
check_docker() {
  info "检查 Docker 环境…"
  if ! command -v docker >/dev/null 2>&1; then
    err "未检测到 docker。请先安装 Docker：https://docs.docker.com/engine/install/"
    exit 1
  fi
  if ! docker info >/dev/null 2>&1; then
    err "docker 守护进程未运行或当前用户无权限。请启动 Docker（或用 sudo）后重试。"
    exit 1
  fi
  if docker compose version >/dev/null 2>&1; then
    COMPOSE="docker compose"
  elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE="docker-compose"
  else
    err "未检测到 docker compose 插件。请安装 Docker Compose v2。"
    exit 1
  fi
  ok "Docker 就绪（$COMPOSE）"
}

# ---------- 随机令牌 ----------
gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

# ---------- 交互读取（隐藏输入用于密钥）----------
ask() {   # ask VAR "提示" "默认值"
  local __var="$1" __prompt="$2" __default="${3:-}" __input=""
  if [ -n "$__default" ]; then
    printf "${C_BOLD}%s${C_RESET} ${C_DIM}[%s]${C_RESET}: " "$__prompt" "$__default"
  else
    printf "${C_BOLD}%s${C_RESET}: " "$__prompt"
  fi
  read -r __input </dev/tty || true
  [ -z "$__input" ] && __input="$__default"
  printf -v "$__var" '%s' "$__input"
}

ask_secret() {  # ask_secret VAR "提示"
  local __var="$1" __prompt="$2" __input=""
  printf "${C_BOLD}%s${C_RESET}: " "$__prompt"
  read -rs __input </dev/tty || true
  echo
  printf -v "$__var" '%s' "$__input"
}

main() {
  banner
  check_docker

  # 已存在 .env 时确认是否覆盖
  if [ -f .env ]; then
    warn "检测到已存在 .env 配置。"
    ask OVERWRITE "是否重新生成 .env？会备份旧文件 (y/N)" "N"
    case "$OVERWRITE" in
      y|Y|yes|YES)
        cp .env ".env.bak.$(date +%Y%m%d_%H%M%S)"
        ok "旧配置已备份"
        ;;
      *)
        info "保留现有 .env，直接进入构建启动。"
        build_and_up
        return
        ;;
    esac
  fi

  printf "\n${C_CYAN}${C_BOLD}==== 必填 / 推荐参数采集 ====${C_RESET}\n"
  printf "${C_DIM}直接回车使用中括号内默认值；密钥输入时不显示。${C_RESET}\n\n"

  # --- LLM（必填）---
  printf "${C_YELLOW}【1/4】AI 模型通道（必填，OpenAI 兼容接口）${C_RESET}\n"
  ask        LLM_BASE_URL "  LLM base_url" "https://api.deepseek.com/v1"
  ask        LLM_MODEL    "  模型名称"      "deepseek-chat"
  while :; do
    ask_secret LLM_API_KEY "  LLM API Key（必填，形如 sk-...）"
    [ -n "$LLM_API_KEY" ] && break
    err "  API Key 不能为空——这是平台运行的核心，请填入。"
  done
  ok "  模型通道已记录"

  # --- FOFA（推荐）---
  printf "\n${C_YELLOW}【2/4】FOFA Key（推荐，用于自动搜集目标；不填只能手动录目标）${C_RESET}\n"
  ask_secret FOFA_KEY "  FOFA Key（可留空）"
  [ -n "$FOFA_KEY" ] && ok "  FOFA 已配置" || warn "  跳过 FOFA：自动资产搜集将不可用，可稍后在设置页补填"

  # --- 访问令牌（强烈建议）---
  printf "\n${C_YELLOW}【3/4】控制台访问令牌（强烈建议，否则任何人可访问你的控制台）${C_RESET}\n"
  ask GEN_TOKEN "  自动生成一个高强度全权限令牌？(Y/n)" "Y"
  case "$GEN_TOKEN" in
    n|N|no|NO)
      ask_secret AUTOHUNTER_API_TOKEN "  自定义全权限令牌（可留空=不鉴权，危险）"
      ;;
    *)
      AUTOHUNTER_API_TOKEN="$(gen_token)"
      ok "  已生成全权限令牌"
      ;;
  esac

  # --- 端口 ---
  printf "\n${C_YELLOW}【4/4】对外访问端口${C_RESET}\n"
  ask AUTOHUNTER_HOST_PORT "  宿主机端口" "18800"

  # --- 写 .env ---
  info "生成 .env …"
  cp .env.example .env
  set_env LLM_BASE_URL         "$LLM_BASE_URL"
  set_env LLM_MODEL            "$LLM_MODEL"
  set_env LLM_API_KEY          "$LLM_API_KEY"
  set_env FOFA_KEY             "$FOFA_KEY"
  set_env AUTOHUNTER_API_TOKEN "$AUTOHUNTER_API_TOKEN"
  # 端口不在 .env.example 里，追加宿主机端口映射变量
  if grep -q '^AUTOHUNTER_HOST_PORT=' .env; then
    set_env AUTOHUNTER_HOST_PORT "$AUTOHUNTER_HOST_PORT"
  else
    printf "\nAUTOHUNTER_HOST_PORT=%s\n" "$AUTOHUNTER_HOST_PORT" >> .env
  fi
  chmod 600 .env 2>/dev/null || true
  ok ".env 已生成（权限 600）"

  build_and_up
}

# 就地设置 .env 中某个 KEY=VALUE（不存在则追加）
set_env() {
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  local found=0
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in
      "$key="*)
        printf '%s=%s\n' "$key" "$val" >> "$tmp"; found=1 ;;
      *)
        printf '%s\n' "$line" >> "$tmp" ;;
    esac
  done < .env
  [ "$found" -eq 0 ] && printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" .env
}

build_and_up() {
  printf "\n${C_CYAN}${C_BOLD}==== 构建并启动 ====${C_RESET}\n"
  warn "首次构建会拉取镜像 + 编译前端 + 安装挖洞工具（nmap/nuclei/sqlmap 等），可能需要 5-15 分钟。"
  info "开始构建镜像…"
  $COMPOSE up -d --build

  # 端口
  local port
  port="$(grep -E '^AUTOHUNTER_HOST_PORT=' .env 2>/dev/null | tail -1 | cut -d= -f2)"
  [ -z "$port" ] && port="18800"

  # 等待健康
  info "等待服务就绪…"
  local i ready=0
  for i in $(seq 1 30); do
    if curl -fsS --max-time 3 "http://127.0.0.1:${port}/health" >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 2
  done

  echo
  if [ "$ready" -eq 1 ]; then
    ok "AutoHunter 已启动 🎉"
  else
    warn "服务已拉起，但健康检查暂未通过（可能仍在初始化）。可稍后用下方命令查看日志。"
  fi

  print_summary "$port"
}

print_summary() {
  local port="$1"
  local token
  token="$(grep -E '^AUTOHUNTER_API_TOKEN=' .env 2>/dev/null | tail -1 | cut -d= -f2)"
  local ip
  ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; [ -z "$ip" ] && ip="服务器IP"

  printf "\n${C_GREEN}${C_BOLD}============================================================${C_RESET}\n"
  printf "${C_GREEN}${C_BOLD}  部署完成  ·  Powered By StanleyNull${C_RESET}\n"
  printf "${C_GREEN}${C_BOLD}============================================================${C_RESET}\n\n"
  printf "  控制台地址 :  ${C_CYAN}http://%s:%s/${C_RESET}\n" "$ip" "$port"
  printf "  本机访问   :  ${C_CYAN}http://127.0.0.1:%s/${C_RESET}\n" "$port"
  if [ -n "$token" ]; then
    printf "  访问令牌   :  ${C_YELLOW}%s${C_RESET}\n" "$token"
    printf "               ${C_DIM}（登录时填入；请妥善保存，勿泄露）${C_RESET}\n"
  else
    printf "  ${C_RED}访问令牌   :  未设置——任何人可访问！建议编辑 .env 补一个 AUTOHUNTER_API_TOKEN${C_RESET}\n"
  fi
  printf "\n  ${C_BOLD}常用命令${C_RESET}\n"
  printf "    查看日志 :  %s logs -f autohunter\n" "$COMPOSE"
  printf "    停止服务 :  %s down\n" "$COMPOSE"
  printf "    重启服务 :  %s restart autohunter\n" "$COMPOSE"
  printf "\n  ${C_BOLD}下一步${C_RESET}：打开控制台 → 新建挖掘任务 → 填 FOFA 语法或手动目标 → 启动。\n\n"
  printf "  ${C_DIM}⚠ 仅对已获授权的目标使用。本工具遵循 CC BY-NC 4.0，禁止商用。${C_RESET}\n\n"
}

main "$@"
