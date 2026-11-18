"""Three independent public exchange ticker adapters.

Coinbase and Kraken are primary. Bitstamp is a continuously polled/parallel
standby source. All three requests are launched concurrently so fallback
selection never waits for a second sequential network round-trip.
"""
import asyncio
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation

import httpx

from app.quote_engine import RateObservation


COINBASE_TICKER_URL = "https://api.exchange.coinbase.com/products/{product_id}/ticker"
KRAKEN_TICKER_URL = "https://api.kraken.com/0/public/Ticker"
BITSTAMP_TICKER_URL = "https://www.bitstamp.net/api/v2/ticker/{market_symbol}/"


def _decimal_midpoint(bid: object, ask: object) -> Decimal:
    try:
        bid_value, ask_value = Decimal(str(bid)), Decimal(str(ask))
    except (InvalidOperation, TypeError, ValueError):
        raise ValueError("market source returned an invalid bid/ask") from None
    if not bid_value.is_finite() or not ask_value.is_finite() or bid_value <= 0 or ask_value <= 0 or ask_value < bid_value:
        raise ValueError("market source returned an invalid bid/ask")
    return (bid_value + ask_value) / Decimal(2)


def parse_coinbase_midpoint(payload: dict) -> Decimal:
    return _decimal_midpoint(payload.get("bid"), payload.get("ask"))


def parse_kraken_midpoint(payload: dict) -> Decimal:
    if payload.get("error"):
        raise ValueError("Kraken returned a market-data error")
    result = payload.get("result")
    if not isinstance(result, dict) or len(result) != 1:
        raise ValueError("Kraken response did not contain exactly one requested market")
    ticker = next(iter(result.values()))
    try:
        return _decimal_midpoint(ticker["b"][0], ticker["a"][0])
    except (KeyError, IndexError, TypeError):
        raise ValueError("Kraken ticker response is incomplete") from None


def parse_bitstamp_midpoint(payload: dict) -> Decimal:
    return _decimal_midpoint(payload.get("bid"), payload.get("ask"))


async def _fetch_coinbase(client: httpx.AsyncClient, product_id: str, observed_at: datetime) -> RateObservation:
    response = await client.get(COINBASE_TICKER_URL.format(product_id=product_id))
    response.raise_for_status()
    return RateObservation("coinbase", parse_coinbase_midpoint(response.json()), observed_at)


async def _fetch_kraken(client: httpx.AsyncClient, pair: str, observed_at: datetime) -> RateObservation:
    response = await client.get(KRAKEN_TICKER_URL, params={"pair": pair})
    response.raise_for_status()
    return RateObservation("kraken", parse_kraken_midpoint(response.json()), observed_at)


async def _fetch_bitstamp(client: httpx.AsyncClient, market_symbol: str, observed_at: datetime) -> RateObservation:
    response = await client.get(BITSTAMP_TICKER_URL.format(market_symbol=market_symbol))
    response.raise_for_status()
    return RateObservation("bitstamp", parse_bitstamp_midpoint(response.json()), observed_at)


def _primary_spread_bps(a: Decimal, b: Decimal) -> int:
    midpoint = (a + b) / Decimal(2)
    return int((abs(a - b) / midpoint * Decimal(10_000)).to_integral_value(rounding="ROUND_UP"))


async def fetch_three_exchange_observations(
    *,
    coinbase_product_id: str,
    kraken_pair: str,
    bitstamp_market_symbol: str,
    now: datetime | None = None,
    timeout_seconds: float = 3.0,
    max_primary_divergence_bps: int = 150,
    client: httpx.AsyncClient | None = None,
) -> list[RateObservation]:
    """Fetch primary prices first, with the backup request already running.

    When primary prices agree, return immediately without waiting for Bitstamp.
    When they diverge, await the already-in-flight backup request. If it is
    unavailable, the quote engine will fail closed rather than use one source.
    """
    product = coinbase_product_id.strip().upper()
    pair = kraken_pair.strip()
    market = bitstamp_market_symbol.strip().lower()
    if not product or "/" in product or not pair or not market or not market.isalnum():
        raise ValueError("explicit Coinbase, Kraken and Bitstamp market mappings are required")
    if max_primary_divergence_bps < 0:
        raise ValueError("primary divergence threshold must be nonnegative")
    observed_at = now or datetime.now(timezone.utc)

    async def fetch_with(active_client: httpx.AsyncClient) -> list[RateObservation]:
        backup_task = asyncio.create_task(_fetch_bitstamp(active_client, market, observed_at))
        try:
            primary_results = await asyncio.gather(
                _fetch_coinbase(active_client, product, observed_at),
                _fetch_kraken(active_client, pair, observed_at),
                return_exceptions=True,
            )
            errors = [item for item in primary_results if isinstance(item, BaseException)]
            if errors:
                backup_task.cancel()
                await asyncio.gather(backup_task, return_exceptions=True)
                raise ValueError("both primary exchange sources are required") from errors[0]

            primary_rows = list(primary_results)
            primary_spread = _primary_spread_bps(
                primary_rows[0].units_per_usd,
                primary_rows[1].units_per_usd,
            )
            if primary_spread <= max_primary_divergence_bps:
                backup_task.cancel()
                await asyncio.gather(backup_task, return_exceptions=True)
                return primary_rows

            backup_result = await asyncio.gather(backup_task, return_exceptions=True)
            if isinstance(backup_result[0], BaseException):
                return primary_rows
            return primary_rows + [backup_result[0]]
        except BaseException:
            if not backup_task.done():
                backup_task.cancel()
                await asyncio.gather(backup_task, return_exceptions=True)
            raise

    if client is not None:
        return await fetch_with(client)
    async with httpx.AsyncClient(timeout=timeout_seconds) as active_client:
        return await fetch_with(active_client)
