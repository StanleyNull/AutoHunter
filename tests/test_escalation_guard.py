"""覆盖 Escalation 闭环收口：升级结果空发射守卫 has_emission。"""
import unittest

from app.tools.escalation_guard import _EMISSION_FIELDS, has_emission


class TestEscalationGuard(unittest.TestCase):
    def test_returns_false_when_not_a_dict(self):
        self.assertFalse(has_emission(None))
        self.assertFalse(has_emission("x"))

    def test_empty_result_rejected(self):
        self.assertFalse(has_emission({}))
        self.assertFalse(has_emission({"poc": "   ", "description": ""}))

    def test_any_emission_passes(self):
        self.assertTrue(has_emission({"description": "接管管理后台"}))
        self.assertTrue(has_emission({"poc": "<script>alert(1)</script>"}))
        self.assertTrue(has_emission({"raw_response": "<html>admin</html>", "poc": ""}))

    def test_all_emission_fields_considered(self):
        # 守卫判定至少看这四个字段；只要一个非空即放行。
        self.assertEqual(set(_EMISSION_FIELDS), {"poc", "raw_request", "raw_response", "description"})


if __name__ == "__main__":
    unittest.main()