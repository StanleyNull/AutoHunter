#!/usr/bin/env python3
"""在服务器 /opt/autohunter 内做部署前备份：stash 未提交改动，并把当前 app 快照到带时间戳目录。"""
import paramiko, sys, datetime

HOST="82.109.60.107"; PORT=22; USER="root"; PASS="txy12344321A."
TS = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
REMOTE="/opt/autohunter"

BACKUP = f"""
set -e
cd {REMOTE}
echo "=== git stash 未提交改动（prefilter.py/orchestrator.py 等） ==="
git stash push -u -m "pre_deploy_backup_{TS}" 2>&1 || echo "stash 跳过(无改动或无 git)"
echo "=== 快照整个项目到 /opt/autohunter_pre_{TS} ==="
cp -a {REMOTE} /opt/autohunter_pre_{TS}
echo "SNAPSHOT_DIR=/opt/autohunter_pre_{TS}"
echo "=== 快照完成，列一下 ==="
ls -d /opt/autohunter_pre_{TS}
du -sh /opt/autohunter_pre_{TS} 2>/dev/null
echo "=== git status after stash ==="
git status --short 2>/dev/null | head
echo "=== DONE ==="
"""

c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
c.connect(HOST,port=PORT,username=USER,password=PASS,timeout=15,look_for_keys=False,allow_agent=False)
i,o,e=c.exec_command(BACKUP,timeout=120)
print(o.read().decode("utf-8","replace"))
err=e.read().decode("utf-8","replace")
if err.strip(): print("---ERR---\n"+err)
c.close()
