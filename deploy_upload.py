#!/usr/bin/env python3
"""把本机 AutoHunter-main 代码树（排除本地专用项）上传到服务器 /opt/autohunter，保留服务器 .env。"""
import paramiko, os, sys

HOST="82.109.60.107"; PORT=22; USER="root"; PASS="txy12344321A."
LOCAL="C:/Users/田心渝/Downloads/AutoHunter-main"
REMOTE="/opt/autohunter"

EXCLUDE_DIRS = {".git", ".workbuddy", "__pycache__", ".pytest_cache", "node_modules",
                "_server_compare", "assets"}  # assets 是二进制资源，服务器已有，且不属代码
EXCLUDE_FILES = {"dbg_tmp.py"}
# 不覆盖服务器 .env（保留真实配置）
PROTECT_ON_SERVER = {".env", ".env.example"}  # .env.example 也保留服务器版（已含注释）

def walk(sftp, local_dir, remote_dir, depth=0):
    count=0
    try:
        names=os.listdir(local_dir)
    except Exception as e:
        print(f"LISTDIR FAIL {local_dir}: {e}")
        return count
    for name in names:
        lp=os.path.join(local_dir,name)
        rp=remote_dir+"/"+name
        try:
            if os.path.isdir(lp):
                if name in EXCLUDE_DIRS:
                    continue
                try:
                    sftp.stat(rp)
                except IOError:
                    sftp.mkdir(rp)
                count+=walk(sftp, lp, rp, depth+1)
            else:
                if name in EXCLUDE_FILES or name in PROTECT_ON_SERVER:
                    continue
                sftp.put(lp, rp)
                count+=1
                if count % 50 == 0:
                    print(f"  ...{count} files", flush=True)
        except Exception as ex:
            print(f"FAIL {rp}: {ex!r}", flush=True)
    return count

c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
try:
    c.connect(HOST,port=PORT,username=USER,password=PASS,timeout=15,look_for_keys=False,allow_agent=False)
    sftp=c.open_sftp()
    n=walk(sftp, LOCAL, REMOTE)
    sftp.close(); c.close()
    print(f"UPLOADED {n} files to {REMOTE} (server .env preserved)")
except Exception as e:
    import traceback
    traceback.print_exc()
    sys.exit(1)
