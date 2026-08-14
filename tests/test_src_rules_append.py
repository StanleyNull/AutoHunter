import unittest

from app.agents.prompts import (
    TASK_SRC_RULES_MAX_CHARS,
    append_task_src_rules,
    reviewer_system_prompt,
    worker_system_prompt,
)


class SrcRulesAppendTest(unittest.TestCase):
    def test_empty_keeps_original(self):
        base = "内置标准"
        self.assertEqual(append_task_src_rules(base, ""), base)
        self.assertEqual(append_task_src_rules(base, "   \n  "), base)
        self.assertEqual(append_task_src_rules(base, None), base)

    def test_appends_without_replacing(self):
        base = "内置标准：不收轰炸"
        out = append_task_src_rules(base, "本校不收弱口令")
        self.assertTrue(out.startswith("内置标准：不收轰炸"))
        self.assertIn("本校不收弱口令", out)
        self.assertIn("叠加在上方内置标准之上，不替换", out)
        self.assertIn("不得放宽内置红线", out)

    def test_reviewer_and_worker_keep_builtin_body(self):
        extra = "重点收越权"
        reviewer = reviewer_system_prompt("edusrc", src_rules=extra)
        worker = worker_system_prompt("edusrc", src_rules=extra)
        builtin_r = reviewer_system_prompt("edusrc")
        builtin_w = worker_system_prompt("edusrc")
        self.assertTrue(reviewer.startswith(builtin_r.rstrip()))
        self.assertTrue(worker.startswith(builtin_w.rstrip()))
        self.assertIn(extra, reviewer)
        self.assertIn(extra, worker)
        self.assertNotEqual(reviewer, builtin_r)
        self.assertNotEqual(worker, builtin_w)

    def test_truncates_oversize_rules(self):
        extra = "A" * (TASK_SRC_RULES_MAX_CHARS + 80)
        out = append_task_src_rules("base", extra)
        self.assertIn("…(截断)", out)
        self.assertLess(len(out), len("base") + len(extra) + 200)


if __name__ == "__main__":
    unittest.main()
