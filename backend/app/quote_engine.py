"""Fail-closed three-source pricing and short-lived quote calculations."""
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal, ROUND_UP
from itertools import combinations
from typing import Iterable


QUOTE_TTL_SECONDS = 15 * 60
MAX_ADMIN_MARGIN_BPS = 5_000
DEFAULT_PRIMARY_DIVERGENCE_BPS = 150


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
    selected_sources: tuple[str, str]
    used_backup_source: bool
    display_rate_source: str
    display_rate_usd_per_unit: Decimal


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _spread_bps(a: Decimal, b: Decimal) -> int:
    midpoint = (a + b) / Decimal(2)
    return int((abs(a - b) / midpoint * Decimal(10_000)).to_integral_value(rounding=ROUND_UP))


def build_locked_quote(
    *,
    price_usd_minor: int,
    payment_decimals: int,
    observations: Iterable[RateObservation],
    now: datetime | None = None,
    ttl_seconds: int = QUOTE_TTL_SECONDS,
    max_observation_age_seconds: int = 30,
    max_source_divergence_bps: int = DEFAULT_PRIMARY_DIVERGENCE_BPS,
    admin_margin_bps: int = 0,
    primary_sources: tuple[str, str] = ("coinbase", "kraken"),
) -> LockedQuote:
    """Use primary pair when they agree; otherwise select the closest valid pair of three.

    All observations must be fetched server-side. The backup source may be absent
    only while the two primary sources agree within the configured threshold.
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
    if len(primary_sources) != 2 or primary_sources[0] == primary_sources[1]:
        raise ValueError("exactly two distinct primary source names are required")

    seen_sources: set[str] = set()
    normalized: dict[str, tuple[Decimal, datetime]] = {}
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
        normalized[source] = (rate, observed)

    first, second = (name.lower() for name in primary_sources)
    if first not in normalized or second not in normalized:
        raise ValueError("both primary rate sources are required")

    primary_spread = _spread_bps(normalized[first][0], normalized[second][0])
    used_backup = False
    if primary_spread <= max_source_divergence_bps:
        selected = (first, second)
    else:
        pairs = list(combinations(normalized.keys(), 2))
        if len(pairs) < 3:
            raise ValueError("primary sources diverge; fresh backup source is required")
        ranked = sorted(
            ((_spread_bps(normalized[a][0], normalized[b][0]), a, b) for a, b in pairs),
            key=lambda item: (item[0], item[1], item[2]),
        )
        selected_spread, selected_a, selected_b = ranked[0]
        if selected_spread > max_source_divergence_bps:
            raise ValueError("no two of three independent sources agree within the safety threshold")
        selected = (selected_a, selected_b)
        used_backup = True

    selected_rates = [normalized[name][0] for name in selected]
    consensus_rate = sum(selected_rates, Decimal(0)) / Decimal(2)
    selected_spread = _spread_bps(selected_rates[0], selected_rates[1])

    # The customer-facing display is the highest USD value per one payment
    # unit, i.e. the lowest payment-units-per-USD observation. Exclude any
    # fresh source that is still an outlier versus the accepted consensus.
    display_eligible = {
        source: rate
        for source, (rate, _observed) in normalized.items()
        if _spread_bps(rate, consensus_rate) <= max_source_divergence_bps
    }
    if not display_eligible:
        raise ValueError("no market source is eligible for customer-facing display")
    display_rate_source = min(display_eligible, key=lambda source: (display_eligible[source], source))
    display_rate_usd_per_unit = Decimal(1) / display_eligible[display_rate_source]

    margin_multiplier = Decimal(10_000 + admin_margin_bps) / Decimal(10_000)
    usd_amount = Decimal(price_usd_minor) / Decimal(100)
    atomic_amount = usd_amount * consensus_rate * margin_multiplier * (Decimal(10) ** payment_decimals)
    payment_amount_minor = int(atomic_amount.to_integral_value(rounding=ROUND_UP))

    snapshot = [
        {
            "source": source,
            "units_per_usd": format(rate, "f"),
            "observed_at": observed.isoformat(),
            "selected_for_quote": source in selected,
            "backup_source": source not in (first, second),
            "usd_per_payment_unit": format(Decimal(1) / rate, "f"),
            "display_eligible": source in display_eligible,
            "best_display_rate": source == display_rate_source,
        }
        for source, (rate, observed) in sorted(normalized.items())
    ]
    return LockedQuote(
        payment_amount_minor=payment_amount_minor,
        units_per_usd=consensus_rate,
        rate_spread_bps=selected_spread,
        issued_at=current,
        expires_at=current + timedelta(seconds=ttl_seconds),
        source_snapshot=snapshot,
        selected_sources=selected,
        used_backup_source=used_backup,
        display_rate_source=display_rate_source,
        display_rate_usd_per_unit=display_rate_usd_per_unit,
    )


def trusted_payment_started_in_window(
    *,
    first_seen_at: datetime,
    quote_issued_at: datetime,
    quote_expires_at: datetime,
) -> bool:
    """Use trusted provider/node first-seen time, never a client clock or claim."""
    first_seen = _utc(first_seen_at)
    return _utc(quote_issued_at) <= first_seen <= _utc(quote_expires_at)
