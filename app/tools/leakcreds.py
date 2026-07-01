"""泄露凭证查询（可选情报源接入点）。

搜集资产时可顺带查询某域名相关的泄露账号密码，作为 worker 深挖的额外线索。
凭证情报源属于外部数据源，需自行接入：默认未配置任何数据源，此时恒返回空结果，
不发起网络请求、不含任何外部服务地址或密钥，搜集/挖掘主流程照常运行。

接入方式：在此实现 `query_leaked_creds(domain, max_creds)`，
返回 {ok, domain, creds:[{host, username, password, path, score}], note}。

Powered By StanleyNull  
"""
from __future__ import annotations

from typing import Any


def query_leaked_creds(domain: str, max_creds: int = 12) -> dict[str, Any]:
    """默认实现：未配置凭证情报源，返回空凭证列表。"""
    return {
        "ok": False,
        "domain": (domain or "").strip().lower(),
        "creds": [],
        "note": "未配置凭证情报源",
    }
