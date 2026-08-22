import unittest

from app.config import LLMConfig, worker_config
from app.llm.client import LLMClient
from app.orchestrator import TaskRunner


class ModelTierRoutingTest(unittest.TestCase):
    def setUp(self):
        self._saved_strong = worker_config.strong_model
        self._saved_weak = worker_config.weak_model
        worker_config.strong_model = "strong-model"
        worker_config.weak_model = "weak-model"

    def tearDown(self):
        worker_config.strong_model = self._saved_strong
        worker_config.weak_model = self._saved_weak

    def test_no_tier_config_returns_default(self):
        worker_config.strong_model = ""
        worker_config.weak_model = ""
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier({}, "edusrc", None, True),
            "default",
        )

    def test_deepen_target_strong(self):
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier({}, "edusrc", {"foothold": "x"}, True),
            "strong",
        )

    def test_enterprise_strong(self):
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier({}, "enterprise", None, False),
            "strong",
        )

    def test_auth_context_strong(self):
        meta = {"auth_context": {"status": "logged_in"}}
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier(meta, "edusrc", None, True),
            "strong",
        )

    def test_simple_edu_weak(self):
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier({}, "edusrc", None, True),
            "weak",
        )

    def test_edu_with_chain_hints_not_weak(self):
        meta = {"attack_chain_hints": [{"fingerprint": "spring", "attack_chain": "x"}]}
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier(meta, "edusrc", None, True),
            "default",
        )

    def test_edu_with_intel_block_not_weak(self):
        meta = {"intel_block": "命中情报"}
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier(meta, "edusrc", None, True),
            "default",
        )

    def test_unknown_src_normalized_to_edu_weak(self):
        # normalize_src_type 把未知 src 归一为 edusrc；无认证/无情报的普通目标走弱模型。
        self.assertEqual(
            TaskRunner._resolve_worker_model_tier({}, "others", None, False),
            "weak",
        )

    def test_worker_llm_override_returns_new_client(self):
        base = LLMClient(providers=[LLMConfig(api_key="k", model="default-model")])
        strong = TaskRunner._worker_llm_for_tier(base, "strong")
        self.assertEqual(strong.providers[0].model, "strong-model")
        weak = TaskRunner._worker_llm_for_tier(base, "weak")
        self.assertEqual(weak.providers[0].model, "weak-model")

    def test_worker_llm_default_returns_same(self):
        base = LLMClient(providers=[LLMConfig(api_key="k", model="default-model")])
        same = TaskRunner._worker_llm_for_tier(base, "default")
        self.assertIs(same, base)


if __name__ == "__main__":
    unittest.main()
