#!/usr/bin/env python3
"""拉取服务器 /opt/autohunter 关键文件到本地临时目录，用于差异比对（只读，不写服务器）。"""
import paramiko, os, sys

HOST="82.109.60.107"; PORT=22; USER="root"; PASS="txy12344321A."
REMOTE_BASE="/opt/autohunter"
LOCAL_BASE="C:/Users/田心渝/Downloads/AutoHunter-main/_server_compare"
FILES=[
    "app/agents/worker.py",
    "app/agents/reviewer.py",
    "app/schemas.py",
    "docker-compose.yml",
    ".env",
    "Dockerfile",
    "requirements.txt",
]

c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    c.connect(HOST,port=PORT,username=USER,password=PASS,timeout=15,look_for_keys=False,allow_agent=False)
except Exception as e:
    print("SSH FAILED",e); sys.exit(2)

sftp=c.open_sftp()
for f in FILES:
    local=os.path.join(LOCAL_BASE, f.replace("/","__"))
    os.makedirs(os.path.dirname(local), exist_ok=True)
    try:
        sftp.get(REMOTE_BASE + "/" + f, local)
        print("FETCHED", f)
    except Exception as e:
        print("SKIP", f, "->", e)
sftp.close(); c.close()
print("DONE")
