"""Load reviewed market mappings and normalize spot prices to payment units per USD.

Only direct USD spot markets are accepted in this phase. Crosses, stablecoin
assumptions, unreviewed symbols, and missing exchange mappings fail closed.
"""
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session
import httpx

from app.models import ExchangeMarketMapping
from app.quote_engine import RateObservation
from app.rate_sources import fetch_three_exchange_observations


SUPPORTED_SOURCES = frozenset({"coinbase", "kraken", "bitstamp"})


@dataclass(frozen=True)
class ExchangeMarketSpec:
    source: str
    market_symbol: str
    market_base_currency: str
    market_quote_currency: str


def load_enabled_market_specs(
    db: Session,
    *,
    payment_asset_id: int,
    payment_currency: str,
) -> tuple[ExchangeMarketSpec, ...]:
    """Return exactly one reviewed, enabled USD spot market per independent source."""
    currency = payment_currency.strip().upper()
    if not currency or currency == "USD":
        raise ValueError("a non-USD payment currency is required")
    rows = db.execute(
        select(ExchangeMarketMapping).where(
            ExchangeMarketMapping.payment_asset_id == payment_asset_id,
            ExchangeMarketMapping.is_enabled.is_(True),
        )
    ).scalars().all()
    specs = tuple(
        ExchangeMarketSpec(
            source=row.source.strip().lower(),
            market_symbol=row.market_symbol.strip(),
            market_base_currency=row.market_base_currency.strip().upper(),
            market_quote_currency=row.market_quote_currency.strip().upper(),
        )
        for row in rows
    )
    if len(specs) != 3 or {spec.source for spec in specs} != SUPPORTED_SOURCES:
        raise ValueError("exactly one enabled market mapping for each independent source is required")
    for spec in specs:
        if not spec.market_symbol or not (
            (spec.market_base_currency == currency and spec.market_quote_currency == "USD")
            or (spec.market_base_currency == "USD" and spec.market_quote_currency == currency)
        ):
            raise ValueError("market mapping must be a direct spot pair between the payment asset and USD")
    return specs


def normalize_market_midpoint(
    midpoint: Decimal,
    *,
    market_base_currency: str,
    market_quote_currency: str,
    payment_currency: str,
) -> Decimal:
    """Convert quote-currency-per-base-currency into payment units per USD."""
    base = market_base_currency.strip().upper()
    quote = market_quote_currency.strip().upper()
    payment = payment_currency.strip().upper()
    if not midpoint.is_finite() or midpoint <= 0:
        raise ValueError("market midpoint must be finite and positive")
    if base == payment and quote == "USD":
        return Decimal(1) / midpoint
    if base == "USD" and quote == payment:
        return midpoint
    raise ValueError("market pair does not directly represent the payment asset against USD")


async def fetch_payment_asset_observations(
    *,
    payment_currency: str,
    mappings: Iterable[ExchangeMarketSpec],
    now: datetime | None = None,
    timeout_seconds: float = 3.0,
    client: httpx.AsyncClient | None = None,
) -> list[RateObservation]:
    """Fetch the three explicitly mapped markets and normalize their orientations."""
    currency = payment_currency.strip().upper()
    specs = tuple(mappings)
    if len(specs) != 3 or {item.source for item in specs} != SUPPORTED_SOURCES:
        raise ValueError("exactly one mapping for Coinbase, Kraken and Bitstamp is required")
    by_source = {item.source: item for item in specs}
    for item in specs:
        if not item.market_symbol or not (
            (item.market_base_currency == currency and item.market_quote_currency == "USD")
            or (item.market_base_currency == "USD" and item.market_quote_currency == currency)
        ):
            raise ValueError("each source must map the payment asset directly against USD")

    raw = await fetch_three_exchange_observations(
        coinbase_product_id=by_source["coinbase"].market_symbol,
        kraken_pair=by_source["kraken"].market_symbol,
        bitstamp_market_symbol=by_source["bitstamp"].market_symbol,
        now=now,
        timeout_seconds=timeout_seconds,
        client=client,
    )
    normalized: list[RateObservation] = []
    for observation in raw:
        spec = by_source.get(observation.source)
        if spec is None:
            raise ValueError("rate observation has no reviewed market mapping")
        normalized.append(
            RateObservation(
                source=observation.source,
                units_per_usd=normalize_market_midpoint(
                    observation.units_per_usd,
                    market_base_currency=spec.market_base_currency,
                    market_quote_currency=spec.market_quote_currency,
                    payment_currency=currency,
                ),
                observed_at=observation.observed_at,
            )
        )
    return normalized
