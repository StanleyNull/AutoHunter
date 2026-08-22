from __future__ import annotations

from unittest.mock import Mock

from app.agents.worker import Worker


def _make_worker(target: str = "http://example.com") -> Worker:
    worker = Worker.__new__(Worker)
    worker.target = target
    worker.deepen_context = None
    worker.target_meta = {}
    worker._emit = Mock()
    return worker


class _ReconExecutor:
    """模拟 recon 用 executor：http_request 按 url 返回预设响应；无 analyze_javascript。"""

    def __init__(self, pages: dict | None = None):
        self._pages = pages or {}
        self.http_request = Mock(side_effect=self._do_req)
        self.session_set = Mock()

    def _do_req(self, url, method="GET", follow_redirects=False):
        key = url.rstrip("/")
        p = self._pages.get(url) or self._pages.get(key)
        if p is not None:
            return {"ok": True, "status_code": p.get("status_code", 200), "url": url,
                    "final_url": url, "body": p.get("body", ""), "response_headers": p.get("response_headers", {})}
        return {"ok": True, "status_code": 404, "url": url, "body": "", "response_headers": {}}


def test_business_flow_clusters_endpoints_by_stage():
    worker = _make_worker()
    apis = [
        "http://example.com/api/login",
        "http://example.com/api/register",
        "http://example.com/order/123",
        "http://example.com/api/payment",
        "http://example.com/admin/dashboard",
    ]
    block = worker._business_flow_block("http://example.com", apis, [], [])
    assert "业务流状态机映射" in block
    assert "身份认证/登录" in block
    assert "账号注册/开通" in block
    assert "订单/交易" in block
    assert "支付/收银" in block
    assert "后台/管理面" in block
    # 每个阶段都带建议打法
    assert "建议打法：" in block


def test_business_flow_includes_hit_paths_and_meta():
    worker = _make_worker()
    # hit_paths 提供 /api/order/1，meta_exposed 提供 /api/user/9（需鉴权）
    hit_paths = [("/api/order/1", 200)]
    meta_exposed = ["http://example.com/api/user/9（需鉴权）"]
    block = worker._business_flow_block("http://example.com", [], hit_paths, meta_exposed)
    assert "订单/交易" in block
    assert "用户中心/个人资料" in block
    assert "http://example.com/api/user/9" in block  # 暴露端点文本被提取


def test_business_flow_empty_when_no_keywords():
    worker = _make_worker()
    # 全是静态资源/无关路径，不应产出业务流块
    apis = ["http://example.com/static/app.js", "http://example.com/css/style.css", "http://example.com/favicon.ico"]
    block = worker._business_flow_block("http://example.com", apis, [], [])
    assert block == ""


def test_business_flow_dedup_and_caps_per_stage():
    worker = _make_worker()
    # 同一端点重复 + 某阶段超 8 条，验证去重与限长
    apis = [f"http://example.com/api/order/{i}" for i in list(range(12)) + [0, 1]]
    block = worker._business_flow_block("http://example.com", apis, [], [])
    assert "订单/交易" in block
    # range(12)=0..11 共 12 条，再加 [0,1] 两次重复→去重后仍 14 条；显示限 8 条。
    assert "命中 14 个端点" in block
    # 显示的具体端点行不超过 8 个（加阶段标题与建议打法共 10 行内）
    order_lines = [l for l in block.splitlines() if l.startswith("- http")]
    assert len(order_lines) <= 8


def test_business_flow_handles_bad_meta_gracefully():
    worker = _make_worker()
    # meta_exposed 含非字符串/畸形项，不应崩
    meta_exposed = [None, 123, "", "http://example.com/api/pay/1（暴露）"]
    block = worker._business_flow_block("http://example.com", [], [], meta_exposed)
    assert "支付/收银" in block


def test_detect_business_stages_returns_biz_keys_sorted():
    worker = _make_worker()
    # 订单端点数量多（3 个）应排在支付（1 个）之前
    apis = [
        "http://example.com/api/order/1",
        "http://example.com/api/order/2",
        "http://example.com/order/list",
        "http://example.com/api/payment",
    ]
    stages = worker._detect_business_stages("http://example.com", apis, [], [])
    assert "order" in stages
    assert "payment" in stages
    assert stages.index("order") < stages.index("payment")  # 命中多者优先


def test_detect_business_stages_empty_when_no_keywords():
    worker = _make_worker()
    apis = ["http://example.com/static/a.js"]
    assert worker._detect_business_stages("http://example.com", apis, [], []) == []


def test_recon_writes_business_stages_to_separate_field():
    # 全局 recon：选靶暴露端点含订单类 → 业务阶段写入 business_stages，
    # 业务针对性打法写入独立字段 business_attack_chain（不混入编排层注入的 attack_chain_hints，
    # 以免被 _intel_block 的时序窗口吃掉、首轮 LLM 拿不到）。
    pages = {
        "http://example.com/": {
            "status_code": 200,
            "body": "<title>shop</title>",
            "response_headers": {},
        },
        "http://example.com/robots.txt": {"status_code": 404},
        "http://example.com/sitemap.xml": {"status_code": 404},
    }
    worker = _make_worker()
    worker.executor = _ReconExecutor(pages)
    # 预置既有的系统指纹 hints（编排层注入），验证 biz 闭环不污染它
    worker.target_meta = {
        "exposed_endpoints": ["http://example.com/api/order/1（暴露）", "http://example.com/api/payment"],
        "attack_chain_hints": [{"sig": "existing|chain", "vuln_type": "x"}],
    }

    report = worker._run_mandatory_recon()

    stages = worker.target_meta.get("business_stages") or []
    assert "order" in stages
    assert "payment" in stages
    # 编排层注入的 hints 不受 biz 闭环影响（独立字段）
    hints = worker.target_meta.get("attack_chain_hints") or []
    assert any(h.get("sig") == "existing|chain" for h in hints)
    # biz 打法在独立字段
    biz = worker.target_meta.get("business_attack_chain") or []
    assert any("biz:order" in (h.get("fingerprints") or []) for h in biz)


def test_business_chain_block_renders_from_separate_field():
    worker = _make_worker()
    worker.target_meta = {
        "business_stages": ["order", "payment"],
        "business_attack_chain": [
            {"sig": "biz|order", "vuln_type": "idor", "attack_chain": "订单 IDOR：遍历 order_id 查他人订单"},
        ],
    }
    block = worker._business_chain_block()
    assert "业务流针对性打法" in block
    assert "order" in block and "payment" in block
    assert "订单 IDOR" in block
    # 无字段时返回空（不刷屏）
    worker2 = _make_worker()
    worker2.target_meta = {}
    assert worker2._business_chain_block() == ""

