import unittest
from unittest.mock import patch

from app.agents.reviewer import Reviewer, _maybe_accept_write_proof, _maybe_deepen_ignored
from app.agents.write_proof import (
    KIND_AUTHZ_DIFF,
    KIND_SENTINEL,
    KIND_WEAK,
    classify_write_proof,
    has_strong_write_proof,
    should_skip_live_replay,
    weak_write_block_reason,
)
from app.schemas import Finding, Review


def _finding(**kwargs) -> Finding:
    base = {
        "vuln_type": "unauthorized_access",
        "title": "测试系统未授权线索",
        "severity_claimed": "中危",
        "target_url": "https://example.edu.cn/api/test",
        "owner": "测试学校",
        "description": "无需登录可访问接口。",
        "steps": ["访问接口"],
        "poc": "curl https://example.edu.cn/api/test",
        "raw_request": "GET /api/test HTTP/1.1",
        "raw_response": "HTTP/1.1 200 OK\n\n{}",
        "evidence": {"notes": "接口真实存在"},
        "affected_scope": "待确认",
        "kill_chain": [{"method": "接口验证", "detail": "接口无需登录"}],
        "self_check": {
            "is_reflected_xss": False,
            "needs_admin_login": False,
            "needs_mitm": False,
            "is_pure_info_leak": False,
            "scanner_only_no_poc": False,
            "is_public_interface": False,
            "info_leak_hits_strict_list": False,
        },
    }
    base.update(kwargs)
    return Finding(**base)


def _ignored_review(**kwargs) -> Review:
    base = {
        "verdict": "ignored",
        "confidence": "uncertain",
        "score": 1.5,
        "in_scope": True,
        "is_duplicate": False,
        "ignore_reasons": ["未实证下游危害"],
        "reviewer_notes": "不够 accepted。",
    }
    base.update(kwargs)
    return Review(**base)


class WriteProofTest(unittest.TestCase):
    def test_zero_effect_delete_is_weak(self):
        finding = _finding(
            title="事务中心未授权访问 updateDel 接口",
            target_url="https://example.edu.cn/front/zhxg-unauth/dynamic/updateDel",
            description="无需登录可调用删除接口，传入不存在的 id=1 返回操作成功。",
            poc="curl -X POST /front/zhxg-unauth/dynamic/updateDel -d '{\"id\":\"1\"}'",
            raw_request="POST /front/zhxg-unauth/dynamic/updateDel HTTP/1.1\n\n{\"id\":\"1\"}",
            raw_response='HTTP/1.1 200 OK\n\n{"data":0,"message":"操作成功","code":200}',
            evidence={"notes": "id=1 不存在，未证明实际删除任何数据"},
        )
        self.assertEqual(classify_write_proof(finding), KIND_WEAK)
        self.assertTrue(weak_write_block_reason(finding))

    def test_sentinel_lifecycle_is_strong(self):
        finding = _finding(
            title="未授权可增删改自己的测试工单",
            target_url="https://example.edu.cn/api/ticket/delete",
            description="自建哨兵 SRC_TEST_a1b2 后旁路查询可见，删除后查询已消失。",
            poc="curl -X DELETE https://example.edu.cn/api/ticket/delete?id=88",
            raw_request="DELETE /api/ticket/delete?id=88 HTTP/1.1",
            raw_response='HTTP/1.1 200 OK\n\n{"code":200,"msg":"ok"}',
            evidence={"notes": "SRC_TEST_a1b2 删除后查询不存在，before→after 已齐"},
        )
        self.assertEqual(classify_write_proof(finding), KIND_SENTINEL)
        self.assertTrue(has_strong_write_proof(finding))
        self.assertEqual(weak_write_block_reason(finding), "")

    def test_authz_diff_is_strong(self):
        finding = _finding(
            title="未登录 403，登录后可越权修改他人资料",
            target_url="https://example.edu.cn/api/user/update",
            description="未登录对照返回 403，带低权 cookie 后同一 update 返回 200 授权通过。",
            poc="curl -X POST https://example.edu.cn/api/user/update",
            raw_request="POST /api/user/update HTTP/1.1",
            raw_response="HTTP/1.1 200 OK\n\n{\"code\":200}",
            evidence={"notes": "未携带 token 为 403，对照后 200"},
        )
        self.assertEqual(classify_write_proof(finding), KIND_AUTHZ_DIFF)

    def test_delete_in_url_does_not_mean_destructive_sql(self):
        finding = _finding(
            title="未授权删除接口",
            target_url="https://example.edu.cn/api/user/delete",
            poc="curl -X POST https://example.edu.cn/api/user/delete -d id=1",
        )
        skip, why = should_skip_live_replay(finding, finding.poc)
        self.assertTrue(skip)
        self.assertEqual(why, "write_delete")

    def test_drop_table_is_destructive_sql(self):
        finding = _finding(
            vuln_type="sql_injection",
            title="SQL 注入可删表",
            poc="curl 'https://example.edu.cn/a?id=1;DROP TABLE users'",
        )
        skip, why = should_skip_live_replay(finding, finding.poc)
        self.assertTrue(skip)
        self.assertEqual(why, "destructive_sql")

    def test_reviewer_promotes_sentinel_ignored_to_accepted(self):
        finding = _finding(
            title="未授权可增删改自己的测试工单",
            target_url="https://example.edu.cn/api/ticket/delete",
            description="自建哨兵 SRC_TEST_a1b2 后旁路查询可见，删除后查询已消失。",
            poc="curl -X DELETE https://example.edu.cn/api/ticket/delete?id=88",
            evidence={"notes": "SRC_TEST_a1b2 删除后查询不存在，前后对比已齐"},
        )
        review = _ignored_review(ignore_reasons=["未破坏真实数据"])
        self.assertTrue(_maybe_accept_write_proof(finding, review))
        self.assertEqual(review.verdict.value, "accepted")
        self.assertFalse(_maybe_deepen_ignored(finding, review, "edusrc"))

    def test_reviewer_emits_write_kind_when_promoting_sentinel(self):
        finding = _finding(
            title="未授权可增删改自己的测试工单",
            target_url="https://example.edu.cn/api/ticket/delete",
            description="自建哨兵 SRC_TEST_a1b2 后旁路查询可见，删除后查询已消失。",
            poc="curl -X DELETE https://example.edu.cn/api/ticket/delete?id=88",
            evidence={"notes": "SRC_TEST_a1b2 删除后查询不存在，前后对比已齐"},
        )
        events = []
        reviewer = Reviewer(
            llm=object(),
            on_event=lambda kind, data: events.append((kind, data)),
            enable_reproduce=False,
        )

        with patch.object(
            reviewer,
            "_llm_review",
            return_value=_ignored_review(ignore_reasons=["未破坏真实数据"]),
        ):
            review = reviewer.review(finding)

        self.assertEqual(review.verdict.value, "accepted")
        auto_event = next(data for kind, data in events if kind == "review_auto_accept_write")
        self.assertEqual(auto_event["write_kind"], KIND_SENTINEL)
        self.assertNotIn("kind", auto_event)
        self.assertIn("review_done", [kind for kind, _ in events])

    def test_reviewer_does_not_promote_zero_effect(self):
        finding = _finding(
            title="事务中心未授权访问 updateDel 接口",
            target_url="https://example.edu.cn/front/dynamic/updateDel",
            description="传入不存在的 id=1 返回操作成功。",
            poc="curl -X POST /updateDel -d id=1",
            raw_response='{"data":0,"message":"操作成功","code":200}',
            evidence={"notes": "id=1 不存在，未证明实际删除"},
        )
        review = _ignored_review()
        self.assertFalse(_maybe_accept_write_proof(finding, review))
        self.assertEqual(review.verdict.value, "ignored")


if __name__ == "__main__":
    unittest.main()
