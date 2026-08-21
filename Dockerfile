# ===== 阶段 1：构建 Vue 前端 =====
FROM node:20-slim AS frontend
WORKDIR /fe
COPY frontend/package.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build
# 产物在 /fe/../web/dist → /web/dist

# ===== 阶段 2：Python 应用 + 全套安全工具 =====
FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# 系统工具 + 挖洞常用工具
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl wget git ca-certificates \
        nmap \
        python3-pip \
        jq dnsutils iputils-ping netcat-openbsd \
        whatweb \
    && rm -rf /var/lib/apt/lists/*

# sqlmap：官方 PyPI 月度版。构建不依赖 git clone GitHub（国内常超时/失败），
# 也比跟踪 master HEAD 稳。pip 会把 sqlmap 装到 PATH，无需再包一层 wrapper。
RUN pip install --no-cache-dir sqlmap

# ProjectDiscovery 工具：nuclei + httpx（从官方 release 拉二进制，避免装 Go）
# 国内构建优先 ghfast / ghproxy，失败再直连 GitHub。zip 无效则失败，避免镜像 silently 缺工具。
# TARGETARCH 由 buildkit 自动注入(arm64/amd64)
ARG TARGETARCH
RUN set -eux; \
    NUCLEI_VER=3.3.7; HTTPX_VER=1.6.9; \
    cd /tmp; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    fetch_zip() { \
      dest="$1"; shift; \
      for u in "$@"; do \
        echo "GET $u"; \
        if wget -q -T 45 -O "$dest" "$u" && unzip -tq "$dest" >/dev/null 2>&1; then \
          return 0; \
        fi; \
        rm -f "$dest"; \
      done; \
      echo "ERROR: could not download valid $dest" >&2; \
      return 1; \
    }; \
    fetch_zip nuclei.zip \
      "https://ghfast.top/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" \
      "https://ghproxy.net/https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip" \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${TARGETARCH}.zip"; \
    fetch_zip httpx.zip \
      "https://ghfast.top/https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" \
      "https://ghproxy.net/https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip" \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_${TARGETARCH}.zip"; \
    unzip -o nuclei.zip nuclei -d /usr/local/bin/; \
    unzip -o httpx.zip httpx -d /usr/local/bin/; \
    chmod +x /usr/local/bin/nuclei /usr/local/bin/httpx; \
    rm -f /tmp/*.zip; \
    apt-get purge -y unzip; rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 更新 nuclei 模板（失败不阻断构建）
RUN nuclei -update-templates -silent || true

COPY . .

# 拷入前端构建产物（覆盖空的 web/dist）
COPY --from=frontend /web/dist /app/web/dist

# 工作区 + 数据目录（数据目录建议挂卷持久化）
RUN mkdir -p /work /app/data
ENV WORKER_WORK_ROOT=/work \
    DB_PATH=/app/data/autohunter.db

EXPOSE 18800

CMD ["sh", "/app/scripts/run-with-watchdog.sh"]
