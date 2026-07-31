import unittest
from pathlib import Path
import sys
import tempfile
import base64
import time

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.js_analyzer import analyze_javascript, analyze_url


class JsAnalyzerTest(unittest.TestCase):
    def test_jiaozuoye_js_chains_are_detected(self):
        text = """
        var runtimeConfig={
          "upload_token":"abc:def",
          "qiniu_upload_url":"https://up-z0.qiniup.com",
          "qiniu_domain":"https://file-seu.jiaozuoye.online/"
        }
        fetch("/user/get_user_by_phone")
        fetch("/user/login")
        curl -H "X-Parse-Application-Id: APPLICATION_ID" \
          "http://seu.jiaozuoye.online/parse/classes/_User?count=1&limit=0"
        curl -H "X-Parse-Application-Id: APPLICATION_ID" \
          "http://seu.jiaozuoye.online/parse/classes/v5_phone_code?count=1&limit=0"
        """
        result = analyze_javascript(text, base_url="http://seu.jiaozuoye.online", source="unit")
        chains = {c["kind"] for c in result["chains"]}
        self.assertIn("qiniu_upload_xss", chains)
        self.assertIn("parse_unauthorized_read", chains)
        self.assertIn("account_takeover_by_hash", chains)

        findings = {f["kind"] for f in result["findings"]}
        self.assertIn("cloud_upload_token", findings)
        self.assertIn("cloud_upload_endpoint", findings)
        self.assertIn("cloud_file_domain", findings)
        self.assertIn("parse_user_table", findings)

    def test_deep_url_mode_merges_all_js_assets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text(
                '<html><script src="./main.js"></script></html>',
                encoding="utf-8",
            )
            (root / "main.js").write_text(
                'import("./chunk.js"); fetch("/user/get_user_by_phone");',
                encoding="utf-8",
            )
            (root / "chunk.js").write_text(
                'fetch("/user/login"); const upload_token="abc:def";',
                encoding="utf-8",
            )
            result = analyze_url((root / "index.html").as_uri(), max_depth=2)
            self.assertGreaterEqual(result["summary"]["assets"], 3)
            endpoints = {e["kind"] for e in result["endpoint_inventory"]}
            self.assertIn("user_lookup_by_phone", endpoints)
            self.assertIn("login_endpoint", endpoints)
            chains = {c["kind"] for c in result["chains"]}
            self.assertIn("account_takeover_by_hash", chains)

    def test_static_deobfuscation_hints_recover_common_strings(self):
        text = r"""
        const arr = ['\x2fapi\x2fadmin\x2fusers', '/auth/login'];
        fetch(arr[0]);
        const hidden = atob('L2FwaS9zeXN0ZW0vY29uZmlnL2NvbmZpZ0tleS9zeXMudXNlci5pbml0UGFzc3dvcmQ=');
        const reset = '\u002fapi\u002fpassword\u002freset';
        """
        result = analyze_javascript(text, base_url="https://example.edu.cn", source="obf")
        endpoints = {e["url"] for e in result["endpoint_inventory"]}
        self.assertIn("https://example.edu.cn/api/admin/users", endpoints)
        self.assertIn("https://example.edu.cn/api/system/config/configKey/sys.user.initPassword", endpoints)
        self.assertIn("https://example.edu.cn/api/password/reset", endpoints)

    def test_string_concat_obfuscation_is_recovered(self):
        text = """
        const p = '/api/' + 'admin/' + 'export';
        fetch(p);
        """
        result = analyze_javascript(text, base_url="https://example.edu.cn", source="concat")
        endpoints = {e["url"] for e in result["endpoint_inventory"]}
        self.assertIn("https://example.edu.cn/api/admin/export", endpoints)

    def test_sourcemap_sources_content_is_analyzed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "index.html").write_text(
                '<html><script src="./app.js"></script></html>',
                encoding="utf-8",
            )
            (root / "app.js").write_text(
                'console.log("packed");\n//# sourceMappingURL=app.js.map',
                encoding="utf-8",
            )
            (root / "app.js.map").write_text(
                '{"version":3,"sources":["src/api.js"],"sourcesContent":["fetch(\\"/api/export/users\\"); fetch(\\"/auth/login\\");"]}',
                encoding="utf-8",
            )
            result = analyze_url((root / "index.html").as_uri(), max_depth=2)
            self.assertTrue(any(a["kind"] == "sourcemap" for a in result["assets"]))
            endpoints = {e["url"] for e in result["endpoint_inventory"]}
            self.assertIn((root / "api/export/users").as_uri(), endpoints)
            self.assertIn((root / "auth/login").as_uri(), endpoints)

    def test_inline_sourcemap_sources_content_is_analyzed(self):
        smap = '{"version":3,"sources":["src/api.js"],"sourcesContent":["fetch(\\"/api/admin/export\\");"]}'
        encoded = base64.b64encode(smap.encode()).decode()
        text = f'console.log("packed");\\n//# sourceMappingURL=data:application/json;base64,{encoded}'
        result = analyze_javascript(text, base_url="https://example.edu.cn", source="inline-map")
        endpoints = {e["url"] for e in result["endpoint_inventory"]}
        self.assertIn("https://example.edu.cn/api/admin/export", endpoints)

    def test_pathological_string_literals_do_not_hang(self):
        noisy = []
        slash_run = "\\" * 120
        x_run = "x" * 240
        for i in range(2400):
            noisy.append(f"var s{i}='{slash_run}unterminated_{i}\\n")
            noisy.append(f'var t{i}="{x_run}";')
        noisy.append('fetch("/api/admin/export");')
        text = "\n".join(noisy)

        start = time.monotonic()
        result = analyze_javascript(text, base_url="https://example.edu.cn", source="stress")
        elapsed = time.monotonic() - start

        self.assertLess(elapsed, 5.0)
        endpoints = {e["url"] for e in result["endpoint_inventory"]}
        self.assertIn("https://example.edu.cn/api/admin/export", endpoints)

    def test_client_signed_encrypted_api_chain(self):
        """复现客户端签名网关洞：硬编码 AppSecret/AES + 前端签名 + Client* 接口。"""
        text = r"""
        layui.define(function(){
          var config = {
            ClientAppID: "00000001",
            ClientAppSecret: "abcdefg",
            ykeesa: "12345678cgg54321",
            SSOUrl: "/gateway/sso/",
            ApiUrl: "/gateway/sso/bbs/"
          };
          var ykeesa = "12345678cgg54321";
          function sign(code){
            return md5(code + config.ClientAppSecret).swapcase();
          }
          function post(url, body){
            var head = JSON.stringify({AppID:config.ClientAppID, Code:code, Sign:sign(code)});
            headers['HeadJson'] = head;
            var enc = CryptoJS.AES.encrypt(JSON.stringify(body), ykeesa).toString();
            return fetch("/gateway/sso/bbs/Admin/SysOperator/ClientSysOperator", {
              method: "POST",
              body: "json=PWDDATA_" + enc
            });
          }
          post("/gateway/sso/bbs/Admin/SysOperator/ClientSysOperator", {Opt:"Select", iPageSize:3});
        });
        """
        result = analyze_javascript(text, base_url="https://logistics.example.edu.cn", source="client-gateway-fixture")
        kinds = {f["kind"] for f in result["findings"]}
        self.assertIn("client_body_crypto", kinds)
        self.assertIn("client_request_sign", kinds)
        # AES 口令：字面量或混淆变量候选至少命中其一
        self.assertTrue(
            any(f["kind"] == "secret" and "12345678cgg54321" in (f.get("value") or f.get("evidence") or "") for f in result["findings"])
            or any(f["kind"] == "aes_key_candidate" and f.get("value") == "12345678cgg54321" for f in result["findings"])
        )
        self.assertTrue(
            any(f["kind"] == "secret" and "abcdefg" in (f.get("value") or f.get("evidence") or "") for f in result["findings"])
        )
        endpoints = {e["url"] for e in result["endpoint_inventory"]}
        self.assertTrue(any("ClientSysOperator" in u for u in endpoints), endpoints)
        chains = {c["kind"] for c in result["chains"]}
        self.assertIn("client_signed_encrypted_api", chains)


if __name__ == "__main__":
    unittest.main()
