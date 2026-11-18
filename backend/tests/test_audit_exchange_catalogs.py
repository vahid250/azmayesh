from scripts.audit_exchange_catalogs import _kraken_candidates


def test_kraken_audit_keeps_only_exact_direct_usd_candidates():
    payload = {
        "error": [],
        "result": {
            "USDTZUSD": {
                "altname": "USDTUSD",
                "wsname": "USDT/USD",
                "base": "USDT",
                "quote": "ZUSD",
                "status": "online",
            },
            "USDCUSD": {
                "altname": "USDCUSD",
                "wsname": "USDC/USD",
                "base": "USDC",
                "quote": "ZUSD",
                "status": "online",
            },
            "ADAUSDC": {
                "altname": "ADAUSDC",
                "wsname": "ADA/USDC",
                "base": "ADA",
                "quote": "USDC",
                "status": "online",
            },
            "USDCUSDT": {
                "altname": "USDCUSDT",
                "wsname": "USDC/USDT",
                "base": "USDC",
                "quote": "USDT",
                "status": "online",
            },
        },
    }

    rows = _kraken_candidates(payload)

    assert [row["rest_key"] for row in rows] == ["USDTZUSD", "USDCUSD"]
    assert rows[0]["canonical_base_currency"] == "USDT"
    assert rows[0]["canonical_quote_currency"] == "USD"
    assert rows[0]["quote"] == "ZUSD"
    assert all(row["candidate_only"] is True for row in rows)
