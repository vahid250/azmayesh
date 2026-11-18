import httpx

from scripts.audit_exchange_catalogs import _kraken_candidates, _quality_summary, _ticker_observation


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


def test_quality_summary_normalizes_direct_usd_pairs_and_reports_spreads():
    sources = {
        "coinbase": {
            "candidate_markets": [
                {
                    "base_currency": "USDT",
                    "quote_currency": "USD",
                    "bid": "0.99889",
                    "ask": "0.99890",
                    "ticker_http_status": 200,
                    "ticker_retrieved_at": "2026-11-18T08:13:33Z",
                }
            ]
        },
        "kraken": {
            "candidate_markets": [
                {
                    "canonical_base_currency": "USDT",
                    "canonical_quote_currency": "USD",
                    "bid": "0.99886",
                    "ask": "0.99887",
                    "ticker_http_status": 200,
                    "ticker_retrieved_at": "2026-11-18T08:13:33Z",
                }
            ]
        },
        "bitstamp": {
            "candidate_markets": [
                {
                    "base_currency": "USDT",
                    "counter_currency": "USD",
                    "bid": "0.99885",
                    "ask": "0.99886",
                    "ticker_http_status": 200,
                    "ticker_retrieved_at": "2026-11-18T08:13:33Z",
                }
            ]
        },
    }

    summary = _quality_summary(sources)

    assert summary["USDT"]["valid_ticker_sources"] == ["coinbase", "kraken", "bitstamp"]
    assert len(summary["USDT"]["pairwise_divergence"]) == 3
    assert summary["USDT"]["candidate_only"] is True
    assert summary["USDT"]["mapping_approved"] is False
    assert summary["USDT"]["observations"][0]["spread_bps"] == "0.1001"


def test_quality_summary_excludes_ticker_errors_and_cross_pairs():
    sources = {
        "coinbase": {
            "candidate_markets": [
                {
                    "base_currency": "ADA",
                    "quote_currency": "USDC",
                    "bid": "0.5",
                    "ask": "0.6",
                    "ticker_http_status": 200,
                }
            ]
        },
        "kraken": {
            "candidate_markets": [
                {
                    "canonical_base_currency": "USDC",
                    "canonical_quote_currency": "USD",
                    "ticker_http_status": 200,
                    "ticker_error": "ticker unavailable",
                }
            ]
        },
        "bitstamp": {"candidate_markets": []},
    }

    summary = _quality_summary(sources)

    assert summary["USDC"]["valid_ticker_sources"] == []
    assert summary["USDC"]["pairwise_divergence"] == []
