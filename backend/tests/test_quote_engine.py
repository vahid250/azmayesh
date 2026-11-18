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


def rates(coinbase="1.0000", kraken="1.0010", bitstamp="1.0005", age_seconds=5):
    rows = [
        RateObservation("coinbase", Decimal(coinbase), NOW - timedelta(seconds=age_seconds)),
        RateObservation("kraken", Decimal(kraken), NOW - timedelta(seconds=age_seconds)),
    ]
    if bitstamp is not None:
        rows.append(RateObservation("bitstamp", Decimal(bitstamp), NOW - timedelta(seconds=age_seconds)))
    return rows


def test_quote_uses_primary_pair_when_they_agree():
    quote = build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=rates(), now=NOW)
    assert quote.expires_at - quote.issued_at == timedelta(seconds=QUOTE_TTL_SECONDS)
    assert quote.payment_amount_minor == 1_000_500
    assert quote.units_per_usd == Decimal("1.0005")
    assert quote.selected_sources == ("coinbase", "kraken")
    assert quote.used_backup_source is False


def test_disagreement_uses_closest_two_of_three_and_marks_backup():
    # Primary rates differ by about 10%; Bitstamp is close to Coinbase.
    quote = build_locked_quote(
        price_usd_minor=100,
        payment_decimals=6,
        observations=rates("1.0000", "1.1000", "1.0010"),
        now=NOW,
    )
    assert set(quote.selected_sources) == {"bitstamp", "coinbase"}
    assert quote.used_backup_source is True
    assert quote.units_per_usd == Decimal("1.0005")
    selected = {item["source"] for item in quote.source_snapshot if item["selected_for_quote"]}
    assert selected == {"coinbase", "bitstamp"}


def test_disagreement_without_backup_fails_closed():
    with pytest.raises(ValueError, match="fresh backup"):
        build_locked_quote(
            price_usd_minor=100,
            payment_decimals=6,
            observations=rates("1.0", "1.1", None),
            now=NOW,
        )


def test_no_two_of_three_within_threshold_fails_closed():
    with pytest.raises(ValueError, match="no two"):
        build_locked_quote(
            price_usd_minor=100,
            payment_decimals=6,
            observations=rates("1.0", "1.1", "1.2"),
            now=NOW,
        )


def test_quote_rejects_one_source_or_duplicate_source_names():
    with pytest.raises(ValueError, match="both primary"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=rates()[:1], now=NOW)
    duplicate = [
        RateObservation("coinbase", Decimal("1"), NOW),
        RateObservation("coinbase", Decimal("1"), NOW),
    ]
    with pytest.raises(ValueError, match="independent"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=duplicate, now=NOW)


def test_quote_rejects_stale_or_future_observations():
    with pytest.raises(ValueError, match="stale"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=rates(age_seconds=31), now=NOW)
    future = [
        RateObservation("coinbase", Decimal("1"), NOW + timedelta(seconds=10)),
        RateObservation("kraken", Decimal("1"), NOW + timedelta(seconds=10)),
    ]
    with pytest.raises(ValueError, match="future"):
        build_locked_quote(price_usd_minor=100, payment_decimals=6, observations=future, now=NOW)


def test_manager_margin_is_applied_to_customer_amount_and_rounds_up():
    quote = build_locked_quote(
        price_usd_minor=100,
        payment_decimals=2,
        observations=rates("1", "1", "1"),
        now=NOW,
        admin_margin_bps=100,
    )
    assert quote.payment_amount_minor == 101


def test_quote_lifetime_cannot_exceed_fifteen_minutes():
    with pytest.raises(ValueError, match="900"):
        build_locked_quote(
            price_usd_minor=100,
            payment_decimals=2,
            observations=rates(),
            now=NOW,
            ttl_seconds=901,
        )


def test_payment_is_eligible_only_if_trusted_first_seen_is_in_quote_window():
    expiry = NOW + timedelta(minutes=15)
    assert trusted_payment_started_in_window(first_seen_at=expiry, quote_issued_at=NOW, quote_expires_at=expiry)
    assert not trusted_payment_started_in_window(
        first_seen_at=expiry + timedelta(seconds=1), quote_issued_at=NOW, quote_expires_at=expiry
    )
    assert not trusted_payment_started_in_window(
        first_seen_at=NOW - timedelta(seconds=1), quote_issued_at=NOW, quote_expires_at=expiry
    )
