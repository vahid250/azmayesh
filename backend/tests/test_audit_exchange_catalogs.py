import httpx

from scripts.audit_exchange_catalogs import _kraken_candidates, _ticker_observation


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


def test_kraken_ticker_audit_records_bid_ask_and_response_time():
    def handler(request):
        assert request.url.params["pair"] == "USDTUSD"
        return httpx.Response(
            200,
            json={"error": [], "result": {"USDTZUSD": {"b": ["0.999", "10"], "a": ["1.001", "10"]}}},
        )

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        row = _ticker_observation(client, "kraken", {"altname": "USDTUSD"})

    assert row["ticker_http_status"] == 200
    assert row["bid"] == "0.999"
    assert row["ask"] == "1.001"
    assert row["ticker_retrieved_at"]


def test_ticker_audit_rejects_invalid_bid_ask():
    def handler(request):
        return httpx.Response(200, json={"bid": "2", "ask": "1"})

    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        row = _ticker_observation(client, "coinbase", {"product_id": "USDT-USD"})

    assert "ticker_error" in row
