#!/usr/bin/env bash
# ============================================================================
#  AutoHunter 引导安装脚本
#  Powered By StanleyNull
#
#  用法：
#      bash scripts/install.sh
#
#  作用：
#      检查环境 → 交互式采集参数 → 生成 .env → 构建并启动容器
# ============================================================================

set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

# ============================================================================
# 全局变量
# ============================================================================

# Docker Compose 命令数组
# 例如：
#   COMPOSE_CMD=(docker compose)
#   COMPOSE_CMD=(docker-compose)
COMPOSE_CMD=()

# 默认配置
DEFAULT_LLM_BASE_URL="https://api.deepseek.com/v1"
DEFAULT_LLM_MODEL="deepseek-chat"
DEFAULT_HOST_PORT="18800"

# ============================================================================
# 颜色
# ============================================================================

if [ -t 1 ]; then
    C_RESET="\033[0m"
    C_CYAN="\033[36m"
    C_GREEN="\033[32m"
    C_YELLOW="\033[33m"
    C_RED="\033[31m"
    C_BOLD="\033[1m"
    C_DIM="\033[2m"
else
    C_RESET=""
    C_CYAN=""
    C_GREEN=""
    C_YELLOW=""
    C_RED=""
    C_BOLD=""
    C_DIM=""
fi

# ============================================================================
# 日志
# ============================================================================

info() {
    printf '%b\n' "${C_CYAN}[*]${C_RESET} $1"
}

ok() {
    printf '%b\n' "${C_GREEN}[✓]${C_RESET} $1"
}

warn() {
    printf '%b\n' "${C_YELLOW}[!]${C_RESET} $1"
}

err() {
    printf '%b\n' "${C_RED}[x]${C_RESET} $1" >&2
}

# ============================================================================
# 错误处理
# ============================================================================

on_error() {
    local exit_code=$?
    local line_no="${1:-unknown}"

    printf '\n'
    err "安装脚本执行失败。"
    err "错误位置：第 ${line_no} 行"
    err "退出码：${exit_code}"

    if [ -n "${COMPOSE_CMD[*]:-}" ]; then
        printf '\n'
        warn "如果 Docker 容器已经创建，可以执行："
        printf '  %s logs --tail=100 autohunter\n' "${COMPOSE_CMD[*]}"
    fi

    exit "$exit_code"
}

trap 'on_error $LINENO' ERR

# ============================================================================
# Banner
# ============================================================================

banner() {
    printf '%b' "${C_CYAN}${C_BOLD}"

    cat <<'BANNER'

    _         _        _   _             _
   / \  _   _| |_ ___ | | | |_   _ _ __ | |_ ___ _ __
  / _ \| | | | __/ _ \| |_| | | | | '_ \| __/ _ \ '__|
 / ___ \ |_| | || (_) |  _  | |_| | | | | ||  __/ |
/_/   \_\__,_|\__\___/|_| |_|\__,_|_| |_|\__\___|_|

         AI 自主漏洞挖掘平台  ·  Autonomous Bug Hunter
                    >>  锁定 · 侦察 · 出洞  <<

BANNER

    printf '%b\n' "${C_RESET}"
    printf '%b\n\n' "${C_DIM}        Powered By StanleyNull${C_RESET}"
}

# ============================================================================
# 检查命令
# ============================================================================

require_command() {
    local command_name="$1"
    local install_hint="${2:-}"

    if ! command -v "$command_name" >/dev/null 2>&1; then
        err "未检测到命令：${command_name}"

        if [ -n "$install_hint" ]; then
            err "$install_hint"
        fi

        exit 1
    fi
}

# ============================================================================
# Docker 环境检查
# ============================================================================

check_docker() {
    info "检查 Docker 环境…"

    # docker
    if ! command -v docker >/dev/null 2>&1; then
        err "未检测到 docker。"
        err "请先安装 Docker：https://docs.docker.com/engine/install/"
        exit 1
    fi

    # Docker daemon
    if ! docker info >/dev/null 2>&1; then
        err "Docker 守护进程未运行，或者当前用户没有 Docker 权限。"
        err "请启动 Docker 后重新执行本脚本。"
        exit 1
    fi

    # Docker Compose v2
    if docker compose version >/dev/null 2>&1; then
        COMPOSE_CMD=(docker compose)

    # Docker Compose v1
    elif command -v docker-compose >/dev/null 2>&1; then
        COMPOSE_CMD=(docker-compose)

    else
        err "未检测到 Docker Compose。"
        err "请安装 Docker Compose v2。"
        exit 1
    fi

    local compose_version
    compose_version="$("${COMPOSE_CMD[@]}" version 2>/dev/null || true)"

    ok "Docker 已就绪"
    info "Compose：${COMPOSE_CMD[*]}"
    info "版本：${compose_version}"
}

# ============================================================================
# 检查 curl
# ============================================================================

check_curl() {
    if ! command -v curl >/dev/null 2>&1; then
        warn "未检测到 curl。"
        warn "安装完成后将无法执行自动健康检查。"
        return 0
    fi

    ok "curl 已就绪"
}

# ============================================================================
# 随机 Token
# ============================================================================

gen_token() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
        return 0
    fi

    if [ -r /dev/urandom ]; then
        head -c 32 /dev/urandom \
            | od -An -tx1 \
            | tr -d ' \n'
        return 0
    fi

    # 极端情况下使用时间 + PID
    printf '%s%s%s' \
        "$(date +%s)" \
        "$$" \
        "$RANDOM"
}

# ============================================================================
# 交互读取
# ============================================================================

ask() {
    local __var="$1"
    local __prompt="$2"
    local __default="${3:-}"
    local __input=""

    if [ -n "$__default" ]; then
        printf '%b' \
            "${C_BOLD}${__prompt}${C_RESET} ${C_DIM}[${__default}]${C_RESET}: "
    else
        printf '%b' "${C_BOLD}${__prompt}${C_RESET}: "
    fi

    if ! IFS= read -r __input </dev/tty; then
        __input=""
    fi

    if [ -z "$__input" ]; then
        __input="$__default"
    fi

    printf -v "$__var" '%s' "$__input"
}

ask_secret() {
    local __var="$1"
    local __prompt="$2"
    local __input=""

    printf '%b' "${C_BOLD}${__prompt}${C_RESET}: "

    if ! IFS= read -r -s __input </dev/tty; then
        __input=""
    fi

    printf '\n'

    printf -v "$__var" '%s' "$__input"
}

# ============================================================================
# 验证端口
# ============================================================================

validate_port() {
    local port="$1"

    if ! [[ "$port" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
        return 1
    fi

    return 0
}

# ============================================================================
# 检查端口是否已经占用
# ============================================================================

check_port() {
    local port="$1"

    if command -v lsof >/dev/null 2>&1; then
        if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
            warn "宿主机端口 ${port} 当前已经被占用。"
            return 1
        fi
    elif command -v ss >/dev/null 2>&1; then
        if ss -lnt "( sport = :${port} )" 2>/dev/null \
            | grep -q ":${port}"; then
            warn "宿主机端口 ${port} 当前已经被占用。"
            return 1
        fi
    fi

    return 0
}

# ============================================================================
# 设置 .env
# ============================================================================

set_env() {
    local key="$1"
    local val="$2"
    local tmp

    if [ ! -f .env ]; then
        touch .env
    fi

    tmp="$(mktemp)"

    awk -v key="$key" -v val="$val" '
        BEGIN {
            found = 0
        }

        index($0, key "=") == 1 {
            print key "=" val
            found = 1
            next
        }

        {
            print
        }

        END {
            if (!found) {
                print key "=" val
            }
        }
    ' .env > "$tmp"

    mv "$tmp" .env
}

# ============================================================================
# 检查 .env.example
# ============================================================================

check_env_example() {
    if [ ! -f .env.example ]; then
        err "当前目录没有找到 .env.example"
        err "ROOT_DIR=${ROOT_DIR}"
        exit 1
    fi
}

# ============================================================================
# 创建 .env
# ============================================================================

create_env() {
    info "生成 .env …"

    check_env_example

    cp .env.example .env

    set_env "LLM_BASE_URL" "$LLM_BASE_URL"
    set_env "LLM_MODEL" "$LLM_MODEL"
    set_env "LLM_API_KEY" "$LLM_API_KEY"
    set_env "FOFA_KEY" "$FOFA_KEY"
    set_env "AUTOHUNTER_API_TOKEN" "$AUTOHUNTER_API_TOKEN"
    set_env "AUTOHUNTER_HOST_PORT" "$AUTOHUNTER_HOST_PORT"

    chmod 600 .env 2>/dev/null || true

    ok ".env 已生成"
    info ".env 权限：600"
}

# ============================================================================
# 构建并启动
# ============================================================================

build_and_up() {
    printf '\n'
    printf '%b\n' "${C_CYAN}${C_BOLD}==== 构建并启动 ====${C_RESET}"

    warn "首次构建可能需要较长时间。"
    warn "可能包含：拉取 Docker 镜像、构建前端、安装 nmap/nuclei/sqlmap 等工具。"

    printf '\n'

    info "Docker Compose：${COMPOSE_CMD[*]}"

    info "开始构建镜像…"

    "${COMPOSE_CMD[@]}" up -d --build

    # ------------------------------------------------------------------------
    # 读取端口
    # ------------------------------------------------------------------------

    local port

    port="$(
        awk -F= '
            /^AUTOHUNTER_HOST_PORT=/ {
                value=$2
            }
            END {
                print value
            }
        ' .env 2>/dev/null || true
    )"

    if [ -z "$port" ]; then
        port="$DEFAULT_HOST_PORT"
    fi

    # ------------------------------------------------------------------------
    # 健康检查
    # ------------------------------------------------------------------------

    printf '\n'

    if ! command -v curl >/dev/null 2>&1; then
        warn "未安装 curl，跳过健康检查。"
        print_summary "$port"
        return 0
    fi

    info "等待 AutoHunter 服务就绪…"

    local i
    local ready=0

    for i in $(seq 1 60); do

        if curl \
            -fsS \
            --max-time 3 \
            "http://127.0.0.1:${port}/health" \
            >/dev/null 2>&1; then

            ready=1
            break
        fi

        printf '.'
        sleep 2
    done

    printf '\n\n'

    if [ "$ready" -eq 1 ]; then

        ok "AutoHunter 已启动 🎉"

    else

        warn "服务已经启动，但健康检查暂未通过。"

        printf '\n'
        warn "最近 80 行容器日志："

        "${COMPOSE_CMD[@]}" logs \
            --tail=80 \
            autohunter \
            2>/dev/null || true
    fi

    print_summary "$port"
}

# ============================================================================
# 获取服务器 IP
# ============================================================================

get_server_ip() {

    # Linux
    if command -v hostname >/dev/null 2>&1; then

        local ip

        ip="$(
            hostname -I 2>/dev/null \
            | awk '{print $1}' \
            || true
        )"

        if [ -n "$ip" ]; then
            printf '%s' "$ip"
            return 0
        fi
    fi

    # macOS
    if command -v ipconfig >/dev/null 2>&1; then

        local interface
        local ip

        interface="$(
            route get default 2>/dev/null \
            | awk '/interface:/{print $2}' \
            | head -1 \
            || true
        )"

        if [ -n "$interface" ]; then

            ip="$(
                ipconfig getifaddr "$interface" 2>/dev/null \
                || true
            )"

            if [ -n "$ip" ]; then
                printf '%s' "$ip"
                return 0
            fi
        fi
    fi

    printf '%s' "服务器IP"
}

# ============================================================================
# 输出部署信息
# ============================================================================

print_summary() {
    local port="$1"
    local token=""
    local ip=""

    token="$(
        awk -F= '
            /^AUTOHUNTER_API_TOKEN=/ {
                value=$2
            }
            END {
                print value
            }
        ' .env 2>/dev/null || true
    )"

    ip="$(get_server_ip)"

    printf '\n'

    printf '%b\n' \
        "${C_GREEN}${C_BOLD}============================================================${C_RESET}"

    printf '%b\n' \
        "${C_GREEN}${C_BOLD}  AutoHunter 部署完成 · Powered By StanleyNull${C_RESET}"

    printf '%b\n\n' \
        "${C_GREEN}${C_BOLD}============================================================${C_RESET}"

    printf '  控制台地址 :  %b\n' \
        "${C_CYAN}http://${ip}:${port}/${C_RESET}"

    printf '  本机访问   :  %b\n' \
        "${C_CYAN}http://127.0.0.1:${port}/${C_RESET}"

    if [ -n "$token" ]; then

        printf '  访问令牌   :  %b\n' \
            "${C_YELLOW}${token}${C_RESET}"

        printf '               %b\n' \
            "${C_DIM}（登录时填入；请妥善保存，勿泄露）${C_RESET}"

    else

        printf '  %b\n' \
            "${C_RED}访问令牌   :  未设置——任何人都可能访问控制台！${C_RESET}"

    fi

    printf '\n'

    printf '  %b\n' "${C_BOLD}常用命令${C_RESET}"

    printf '    查看日志 :  %s logs -f autohunter\n' \
        "${COMPOSE_CMD[*]}"

    printf '    停止服务 :  %s down\n' \
        "${COMPOSE_CMD[*]}"

    printf '    重启服务 :  %s restart autohunter\n' \
        "${COMPOSE_CMD[*]}"

    printf '    查看状态 :  %s ps\n' \
        "${COMPOSE_CMD[*]}"

    printf '\n'

    printf '  %b\n' "${C_BOLD}配置文件${C_RESET}"
    printf '    .env      :  ${ROOT_DIR}/.env\n'

    printf '\n'

    printf '  %b\n' "${C_BOLD}下一步${C_RESET}"
    printf '    打开控制台 → 新建挖掘任务 → 配置目标 → 启动任务。\n'

    printf '\n'

    printf '  %b\n\n' \
        "${C_DIM}⚠ 仅对已获授权的目标使用。本工具遵循 CC BY-NC 4.0，禁止商用。${C_RESET}"
}

# ============================================================================
# 读取已有 .env
# ============================================================================

use_existing_env() {
    printf '\n'

    warn "检测到已存在 .env 配置。"

    local overwrite

    ask \
        overwrite \
        "是否重新生成 .env？会备份旧文件 (y/N)" \
        "N"

    case "$overwrite" in

        y|Y|yes|YES)

            local backup

            backup=".env.bak.$(date +%Y%m%d_%H%M%S)"

            cp .env "$backup"

            ok "旧配置已备份：${backup}"

            return 1
            ;;

        *)

            info "保留现有 .env。"
            info "跳过参数采集，直接进入构建启动。"

            return 0
            ;;
    esac
}

# ============================================================================
# 参数采集
# ============================================================================

collect_config() {

    printf '\n'
    printf '%b\n' \
        "${C_CYAN}${C_BOLD}==== 必填 / 推荐参数采集 ====${C_RESET}"

    printf '%b\n\n' \
        "${C_DIM}直接回车使用中括号内默认值；密钥输入时不显示。${C_RESET}"

    # ------------------------------------------------------------------------
    # LLM
    # ------------------------------------------------------------------------

    printf '%b\n' \
        "${C_YELLOW}【1/4】AI 模型通道（必填，OpenAI 兼容接口）${C_RESET}"

    LLM_BASE_URL=""
    LLM_MODEL=""
    LLM_API_KEY=""

    ask \
        LLM_BASE_URL \
        "  LLM base_url" \
        "$DEFAULT_LLM_BASE_URL"

    ask \
        LLM_MODEL \
        "  模型名称" \
        "$DEFAULT_LLM_MODEL"

    while true; do

        ask_secret \
            LLM_API_KEY \
            "  LLM API Key（必填，形如 sk-...）"

        if [ -n "$LLM_API_KEY" ]; then
            break
        fi

        err "  API Key 不能为空。"
    done

    ok "  模型通道已记录"

    # ------------------------------------------------------------------------
    # FOFA
    # ------------------------------------------------------------------------

    printf '\n%b\n' \
        "${C_YELLOW}【2/4】FOFA Key（推荐）${C_RESET}"

    FOFA_KEY=""

    ask_secret \
        FOFA_KEY \
        "  FOFA Key（可留空）"

    if [ -n "$FOFA_KEY" ]; then
        ok "  FOFA 已配置"
    else
        warn "  跳过 FOFA：自动资产搜集将不可用"
    fi

    # ------------------------------------------------------------------------
    # AutoHunter Token
    # ------------------------------------------------------------------------

    printf '\n%b\n' \
        "${C_YELLOW}【3/4】控制台访问令牌${C_RESET}"

    AUTOHUNTER_API_TOKEN=""

    local gen_token_choice

    ask \
        gen_token_choice \
        "  自动生成高强度全权限令牌？(Y/n)" \
        "Y"

    case "$gen_token_choice" in

        n|N|no|NO)

            ask_secret \
                AUTOHUNTER_API_TOKEN \
                "  自定义全权限令牌（可留空=不鉴权，危险）"

            if [ -n "$AUTOHUNTER_API_TOKEN" ]; then
                ok "  自定义访问令牌已配置"
            else
                warn "  未设置访问令牌！"
            fi

            ;;

        *)

            AUTOHUNTER_API_TOKEN="$(gen_token)"

            ok "  已自动生成高强度访问令牌"

            ;;
    esac

    # ------------------------------------------------------------------------
    # Port
    # ------------------------------------------------------------------------

    printf '\n%b\n' \
        "${C_YELLOW}【4/4】对外访问端口${C_RESET}"

    AUTOHUNTER_HOST_PORT=""

    while true; do

        ask \
            AUTOHUNTER_HOST_PORT \
            "  宿主机端口" \
            "$DEFAULT_HOST_PORT"

        if ! validate_port "$AUTOHUNTER_HOST_PORT"; then

            err "端口必须是 1-65535 之间的整数。"
            continue

        fi

        if ! check_port "$AUTOHUNTER_HOST_PORT"; then

            local use_port

            ask \
                use_port \
                "  端口已被占用，是否仍然继续？(y/N)" \
                "N"

            case "$use_port" in
                y|Y|yes|YES)
                    break
                    ;;
                *)
                    continue
                    ;;
            esac

        fi

        break
    done

    ok "  宿主机端口：${AUTOHUNTER_HOST_PORT}"
}

# ============================================================================
# Main
# ============================================================================

main() {

    banner

    # ------------------------------------------------------------------------
    # 基础环境
    # ------------------------------------------------------------------------

    check_docker
    check_curl

    # ------------------------------------------------------------------------
    # 已存在 .env
    # ------------------------------------------------------------------------

    if [ -f .env ]; then

        if use_existing_env; then
            build_and_up
            return 0
        fi

    fi

    # ------------------------------------------------------------------------
    # 参数采集
    # ------------------------------------------------------------------------

    collect_config

    # ------------------------------------------------------------------------
    # 生成 .env
    # ------------------------------------------------------------------------

    create_env

    # ------------------------------------------------------------------------
    # 启动
    # ------------------------------------------------------------------------

    build_and_up
}

main "$@"
