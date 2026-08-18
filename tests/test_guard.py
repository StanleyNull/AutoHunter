import unittest

from app.tools.guard import CommandBlocked, check_command, check_http_request


class GuardDestructiveTest(unittest.TestCase):
    def test_allows_idor_delete(self):
        check_http_request("DELETE", "https://example.edu.cn/api/ticket/delete?id=88")

    def test_allows_src_test_delete_from(self):
        check_command("mysql -e \"DELETE FROM comments WHERE note='SRC_TEST_abc'\"")

    def test_blocks_drop_table_in_edu_mode(self):
        with self.assertRaises(CommandBlocked):
            check_command("mysql -e 'DROP TABLE users'", enterprise=False)

    def test_blocks_drop_in_http_body(self):
        with self.assertRaises(CommandBlocked):
            check_http_request(
                "POST", "https://example.edu.cn/query",
                data="q=1; DROP TABLE users",
            )

    def test_blocks_cache_clear(self):
        with self.assertRaises(CommandBlocked):
            check_http_request("POST", "https://example.edu.cn/admin/cache/clear")

    def test_blocks_sqlmap_dump_all(self):
        with self.assertRaises(CommandBlocked):
            check_command("sqlmap -u http://x/ --dump-all")

    def test_blocks_overwrite_download(self):
        with self.assertRaises(CommandBlocked):
            check_http_request(
                "PUT",
                "https://example.edu.cn/download/notice.pdf",
                data="tampered",
            )

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
