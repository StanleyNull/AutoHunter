import unittest

from app.tools.guard import CommandBlocked, NeedsConfirm, check_command, check_http_request


class GuardDestructiveTest(unittest.TestCase):
    def test_allows_idor_delete(self):
        check_http_request("DELETE", "https://example.edu.cn/api/ticket/delete?id=88")

    def test_allows_src_test_delete_from(self):
        check_command("mysql -e \"DELETE FROM comments WHERE note='SRC_TEST_abc'\"")

    def test_drop_pauses_for_reflection(self):
        with self.assertRaises(NeedsConfirm):
            check_command("mysql -e 'DROP TABLE users'", enterprise=False)

    def test_drop_in_http_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request(
                "POST", "https://example.edu.cn/query",
                data="q=1; DROP TABLE users",
            )

    def test_cache_clear_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request("POST", "https://example.edu.cn/admin/cache/clear")

    def test_sqlmap_dump_all_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_command("sqlmap -u http://x/ --dump-all")

    def test_overwrite_download_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request(
                "PUT",
                "https://example.edu.cn/download/notice.pdf",
                data="tampered",
            )

    def test_confirm_without_reason_still_pauses(self):
        with self.assertRaises(NeedsConfirm):
            check_http_request(
                "POST", "https://example.edu.cn/admin/cache/clear",
                confirm_destructive=True, confirm_reason="",
            )

    def test_confirm_with_reason_allows(self):
        check_http_request(
            "POST", "https://example.edu.cn/admin/cache/clear",
            confirm_destructive=True,
            confirm_reason="只证明接口存在，随后不真正清",
        )

    def test_self_destruct_still_hard_blocks(self):
        with self.assertRaises(CommandBlocked):
            check_command("rm -rf --no-preserve-root /", confirm_destructive=True, confirm_reason="no")

    def test_allows_src_test_upload(self):
        check_http_request(
            "POST",
            "https://example.edu.cn/uploads/SRC_TEST_probe.txt",
            data="ok",
        )

    def test_allows_boolean_sqli(self):
        check_http_request(
            "GET",
            "https://example.edu.cn/item?id=1 AND 1=1",
        )


if __name__ == "__main__":
    unittest.main()
