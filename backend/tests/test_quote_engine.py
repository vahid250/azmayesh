from datetime import datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.quote_engine import (
    QUOTE_TTL_SECONDS,
    RateObservation,
    build_locked_quote,
    trusted_payment_started_in_window,
)


NOW = datetime(2026, 11, 18, 8, 30, tzinfo=timezone.utc)


def two_rates(a="1.0000", b="1.0010", age_seconds=5):
    return [
        RateObservation("coinbase", Decimal(a), NOW - timedelta(seconds=age_seconds)),
        RateObservation("coingecko", Decimal(b), NOW - timedelta(seconds=age_seconds)),
    ]


def test_quote_uses_two_sources_and_locks_exactly_fifteen_minutes():
    quote = build_locked_quote(
        price_usd_minor=100,
        payment_decimals=6,
        observations=two_rates(),
        now=NOW,
    )
    assert quote.expires_at - quote.issued_at == timedelta(seconds=QUOTE_TTL_SECONDS)
    assert quote.payment_amount_minor == 1_001_000
    assert quote.units_per_usd == Decimal("1.0005")
    assert {item["source"] for item in quote.source_snapshot} == {"coinbase", "coingecko"}


def test_quote_rejects_one_source_or_duplicate_source_names():
    with pytest.raises(ValueError, match="at least two"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=two_rates()[:1], now=NOW)
    duplicate = [
        RateObservation("same", Decimal("1"), NOW),
        RateObservation("same", Decimal("1"), NOW),
    ]
    with pytest.raises(ValueError, match="independent"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=duplicate, now=NOW)


def test_quote_fails_closed_when_sources_diverge():
    with pytest.raises(ValueError, match="diverge"):
        build_locked_quote(
            price_usd_minor=100,
            payment_decimals=6,
            observations=two_rates("1", "1.05"),
            now=NOW,
        )


def test_quote_rejects_stale_or_future_observations():
    with pytest.raises(ValueError, match="stale"):
        build_locked_quote(
            price_usd_minor=100,
            payment_decimals=6,
            observations=two_rates(age_seconds=31),
            now=NOW,
        )
    future = [
        RateObservation("one", Decimal("1"), NOW + timedelta(seconds=10)),
        RateObservation("two", Decimal("1"), NOW + timedelta(seconds=10)),
    ]
    with pytest.raises(ValueError, match="future"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=future, now=NOW)


def test_manager_margin_is_applied_to_the_customer_amount_and_rounds_up():
    quote = build_locked_quote(
        price_usd_minor=100,
        payment_decimals=2,
        observations=two_rates("1", "1"),
        now=NOW,
        admin_margin_bps=100,
    )
    assert quote.payment_amount_minor == 102


def test_quote_lifetime_cannot_exceed_fifteen_minutes():
    with pytest.raises(ValueError, match="900"):
        build_locked_quote(
            price_usd_minor=100,
            payment_decimals=2,
            observations=two_rates(),
            now=NOW,
            ttl_seconds=901,
        )


def test_payment_is_eligible_only_if_trusted_first_seen_is_before_expiry():
    expiry = NOW + timedelta(minutes=15)
    assert trusted_payment_started_in_window(
        first_seen_at=expiry - timedelta(seconds=1),
        quote_expires_at=expiry,
    )
    assert trusted_payment_started_in_window(
        first_seen_at=expiry,
        quote_expires_at=expiry,
    )
    assert not trusted_payment_started_in_window(
        first_seen_at=expiry + timedelta(seconds=1),
        quote_expires_at=expiry,
    )
