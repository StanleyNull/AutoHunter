"""开源版一键更新 API 加固回归测试（发布版专属特性）。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import app.api.update as upd  # noqa: E402


class _DummyThread:
    """避免测试里真的起线程 + SIGTERM 打死测试进程。"""

    def __init__(self, *a, **k):
        pass

    def start(self):
        pass


def test_check_non_git_deploy(monkeypatch):
    monkeypatch.setattr(upd, "_is_git_deploy", lambda: False)
    r = upd.check_update()
    assert r["update_available"] is False
    assert r.get("manual_only") is True
    assert "releases_url" in r
    assert "git" in r["error"].lower() or "镜像" in r["error"]


def test_commits_behind_uses_range(monkeypatch):
    """落后数必须用 HEAD..origin/main（旧写法 rev-list HEAD origin/main 是并集，会高估）。"""
    monkeypatch.setattr(upd, "_is_git_deploy", lambda: True)
    seen = []

    def g(*args, timeout=30):
        key = " ".join(args)
        seen.append(key)
        if key.startswith("fetch"):
            return (0, "", "")
        if key == "rev-parse HEAD":
            return (0, "aaaa1111", "")
        if key == "rev-parse origin/main":
            return (0, "bbbb2222", "")
        if key.startswith("diff"):
            return (0, "app/x.py\napp/y.py", "")
        if key.startswith("log"):
            return (0, "msg", "")
        if key.startswith("rev-list --count HEAD..origin/main"):
            return (0, "3", "")
        return (0, "999", "")  # 若误用旧并集写法会拿到 999

    monkeypatch.setattr(upd, "_git", g)
    r = upd.check_update()
    assert r["update_available"] is True
    assert r["commits_behind"] == 3
    assert any(k.startswith("rev-list --count HEAD..origin/main") for k in seen)
    assert r["hot_updateable"] is True  # 仅 app/ 变更可热更


def test_run_needs_rebuild_blocks(monkeypatch):
    monkeypatch.setattr(upd, "_is_git_deploy", lambda: True)

    def g(*args, timeout=30):
        key = " ".join(args)
        if key.startswith("fetch"):
            return (0, "", "")
        if key == "rev-parse HEAD":
            return (0, "aaaa", "")
        if key == "rev-parse origin/main":
            return (0, "bbbb", "")
        if key.startswith("diff"):
            return (0, "frontend/App.vue", "")  # 前端变更需重建
        return (0, "", "")

    monkeypatch.setattr(upd, "_git", g)
    r = upd.run_update()
    assert r["ok"] is False and "重建" in r["error"]


def test_run_concurrency_lock(monkeypatch):
    monkeypatch.setattr(upd, "_is_git_deploy", lambda: True)
    assert upd._update_lock.acquire(blocking=False)  # 模拟已有更新在跑
    try:
        r = upd.run_update()
        assert r["ok"] is False and "已在进行" in r["error"]
    finally:
        upd._update_lock.release()


def test_run_dirty_tree_aborts(monkeypatch):
    monkeypatch.setattr(upd, "_is_git_deploy", lambda: True)

    def g(*args, timeout=30):
        key = " ".join(args)
        if key.startswith("fetch"):
            return (0, "", "")
        if key == "rev-parse HEAD":
            return (0, "aaaa", "")
        if key == "rev-parse origin/main":
            return (0, "bbbb", "")
        if key.startswith("diff"):
            return (0, "app/x.py", "")
        if key.startswith("status"):
            return (0, " M app/x.py", "")  # 工作树有本地改动
        return (0, "", "")

    monkeypatch.setattr(upd, "_git", g)
    monkeypatch.setattr(upd.threading, "Thread", _DummyThread)
    r = upd.run_update()
    assert r["ok"] is False and "本地改动" in r["error"]


def test_run_pip_failure_skips_restart(monkeypatch):
    monkeypatch.setattr(upd, "_is_git_deploy", lambda: True)

    def g(*args, timeout=30):
        key = " ".join(args)
        if key.startswith("fetch"):
            return (0, "", "")
        if key == "rev-parse HEAD":
            return (0, "aaaa", "")
        if key == "rev-parse origin/main":
            return (0, "bbbb", "")
        if key.startswith("diff"):
            return (0, "requirements.txt\napp/x.py", "")
        if key.startswith("status"):
            return (0, "", "")  # 干净
        if key.startswith("pull"):
            return (0, "", "")
        return (0, "", "")

    class _FakePR:
        returncode = 1
        stderr = "dep boom"
        stdout = ""

    monkeypatch.setattr(upd, "_git", g)
    monkeypatch.setattr(upd.subprocess, "run", lambda *a, **k: _FakePR())
    started = {"n": 0}

    class _Spy(_DummyThread):
        def start(self):
            started["n"] += 1

    monkeypatch.setattr(upd.threading, "Thread", _Spy)
    r = upd.run_update()
    assert r["ok"] is False and r["restarted"] is False
    assert "依赖安装失败" in r["error"]
    assert started["n"] == 0, "pip 失败绝不能触发重启（否则崩溃循环）"
