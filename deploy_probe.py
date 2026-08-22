#!/usr/bin/env python3
"""一次性只读探测 82.109.60.107 现状，为部署决策提供依据。不做任何写操作。"""
import paramiko
import sys

HOST = "82.109.60.107"
PORT = 22
USER = "root"
PASS = "txy12344321A."

PROBE = r"""
echo "=== whoami ==="; id
echo "=== docker ==="
if command -v docker >/dev/null 2>&1; then
  docker --version
  docker compose version 2>/dev/null || docker-compose --version 2>/dev/null || echo "no compose plugin"
else
  echo "NO_DOCKER"
fi
echo "=== os ==="
(head -3 /etc/os-release 2>/dev/null)
echo "=== 18800 listener ==="
(ss -ltnp 2>/dev/null | grep -E ":18800" ) || (netstat -ltnp 2>/dev/null | grep 18800) || echo "NO_18800_LISTENER"
echo "=== docker containers ==="
(docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' 2>/dev/null) || echo "DOCKER_PS_UNAVAILABLE"
echo "=== candidate dirs ==="
ls -d /app /work /root/autohunter /opt/autohunter 2>/dev/null || echo "NO_STD_DIRS"
echo "=== git/python on server ==="
(command -v git && git --version) || echo "NO_GIT"
(command -v python3 && python3 --version) || echo "NO_PY3"
echo "=== disk/mem ==="
(df -h / 2>/dev/null | tail -1)
(free -h 2>/dev/null | head -2)
echo "=== DONE ==="
"""

def main():
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        c.connect(HOST, port=PORT, username=USER, password=PASS, timeout=15, look_for_keys=False, allow_agent=False)
    except Exception as e:
        print(f"SSH CONNECT FAILED: {e}")
        sys.exit(2)
    stdin, stdout, stderr = c.exec_command(PROBE, timeout=60)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    print(out)
    if err.strip():
        print("---STDERR---\n" + err)
    c.close()

if __name__ == "__main__":
    main()
