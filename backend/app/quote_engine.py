"""Fail-closed two-source pricing and short-lived quote calculations.

Network adapters belong outside this module. Callers must pass observations
fetched server-side from independent sources; client-supplied rates are never
accepted here.
"""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_UP
from statistics import median
from typing import Iterable


QUOTE_TTL_SECONDS = 15 * 60
MAX_ADMIN_MARGIN_BPS = 5_000


@dataclass(frozen=True)
class RateObservation:
    source: str
    units_per_usd: Decimal
    observed_at: datetime


@dataclass(frozen=True)
class LockedQuote:
    payment_amount_minor: int
    units_per_usd: Decimal
    rate_spread_bps: int
    issued_at: datetime
    expires_at: datetime
    source_snapshot: list[dict]


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def build_locked_quote(
    *,
    price_usd_minor: int,
    payment_decimals: int,
    observations: Iterable[RateObservation],
    now: datetime | None = None,
    ttl_seconds: int = QUOTE_TTL_SECONDS,
    max_observation_age_seconds: int = 30,
    max_source_divergence_bps: int = 150,
    admin_margin_bps: int = 0,
) -> LockedQuote:
    """Build a fixed quote from at least two fresh, independent server observations.

    units_per_usd means how many payment-asset units equal one USD.
    The manager margin is added to the amount payable, never subtracted.
    Amounts are rounded upward to the asset's smallest unit to avoid
    accidentally under-quoting due to decimal truncation.
    """
    current = _utc(now or datetime.now(timezone.utc))
    rows = list(observations)
    if price_usd_minor <= 0:
        raise ValueError("USD price must be positive")
    if not 0 <= payment_decimals <= 18:
        raise ValueError("payment decimals must be between 0 and 18")
    if not 1 <= ttl_seconds <= QUOTE_TTL_SECONDS:
        raise ValueError("quote lifetime must be between 1 and 900 seconds")
    if not 0 <= admin_margin_bps <= MAX_ADMIN_MARGIN_BPS:
        raise ValueError("admin margin is outside the permitted range")
    if len(rows) < 2:
        raise ValueError("at least two independent rate sources are required")

    seen_sources: set[str] = set()
    normalized: list[tuple[str, Decimal, datetime]] = []
    for row in rows:
        source = row.source.strip().lower()
        rate = Decimal(row.units_per_usd)
        observed = _utc(row.observed_at)
        age = (current - observed).total_seconds()
        if not source or source in seen_sources:
            raise ValueError("rate sources must be named and independent")
        if not rate.is_finite() or rate <= 0:
            raise ValueError("rate observations must be finite and positive")
        if age < -5 or age > max_observation_age_seconds:
            raise ValueError("rate observation is stale or from the future")
        seen_sources.add(source)
        normalized.append((source, rate, observed))

    rates = sorted(item[1] for item in normalized)
    midpoint = (rates[0] + rates[-1]) / Decimal(2)
    spread_bps = int((((rates[-1] - rates[0]) / midpoint) * Decimal(10_000)).to_integral_value(rounding=ROUND_UP))
    if spread_bps > max_source_divergence_bps:
        raise ValueError("independent rate sources diverge beyond the safety threshold")

    consensus_rate = Decimal(str(median(rates)))
    margin_multiplier = Decimal(10_000 + admin_margin_bps) / Decimal(10_000)
    usd_amount = Decimal(price_usd_minor) / Decimal(100)
    atomic_amount = usd_amount * consensus_rate * margin_multiplier * (Decimal(10) ** payment_decimals)
    payment_amount_minor = int(atomic_amount.to_integral_value(rounding=ROUND_UP))

    snapshot = [
        {
            "source": source,
            "units_per_usd": format(rate, "f"),
            "observed_at": observed.isoformat(),
        }
        for source, rate, observed in sorted(normalized, key=lambda item: item[0])
    ]
    return LockedQuote(
        payment_amount_minor=payment_amount_minor,
        units_per_usd=consensus_rate,
        rate_spread_bps=spread_bps,
        issued_at=current,
        expires_at=current + timedelta(seconds=ttl_seconds),
        source_snapshot=snapshot,
    )


def trusted_payment_started_in_window(
    *,
    first_seen_at: datetime,
    quote_expires_at: datetime,
) -> bool:
    """Use trusted provider/node first-seen time, never a client clock or claim."""
    return _utc(first_seen_at) <= _utc(quote_expires_at)
