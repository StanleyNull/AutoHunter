#!/usr/bin/env python3
"""只读探查 /opt/autohunter 与现有 autohunter 容器启动方式。"""
import paramiko, sys

HOST="82.109.60.107"; PORT=22; USER="root"; PASS="txy12344321A."

PROBE = r"""
echo "=== /opt/autohunter top ==="
ls -la /opt/autohunter 2>/dev/null | head -40
echo "=== compose/yaml present? ==="
ls -la /opt/autohunter/docker-compose.yml /opt/autohunter/.env 2>/dev/null || echo "no compose/.env at top"
echo "=== git status of /opt/autohunter ==="
(cd /opt/autohunter && git log --oneline -5 2>/dev/null; git status --short 2>/dev/null | head) || echo "not a git repo"
echo "=== autohunter container inspect (start cmd + mounts + env_file) ==="
docker inspect autohunter --format 'IMAGE={{.Config.Image}}
CMD={{json .Config.Cmd}}
Binds={{json .Mounts}}
EnvFile={{json .Config.Env}}' 2>/dev/null | head -40
echo "=== how was it started? look for compose project label ==="
docker inspect autohunter --format 'ComposeProject={{index .Config.Labels "com.docker.compose.project"}}' 2>/dev/null
echo "=== DONE ==="
"""

c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    c.connect(HOST,port=PORT,username=USER,password=PASS,timeout=15,look_for_keys=False,allow_agent=False)
except Exception as e:
    print("SSH FAILED",e); sys.exit(2)
i,o,e=c.exec_command(PROBE,timeout=60)
print(o.read().decode("utf-8","replace"))
err=e.read().decode("utf-8","replace")
if err.strip(): print("---ERR---\n"+err)
c.close()
