from datetime import datetime, timezone
from decimal import Decimal

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database import Base
from app.market_mappings import (
    ExchangeMarketSpec,
    fetch_payment_asset_observations,
    load_enabled_market_specs,
    normalize_market_midpoint,
)
from app.models import ExchangeMarketMapping, PaymentAsset
from app.quote_engine import RateObservation


NOW = datetime(2026, 11, 18, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        asset = PaymentAsset(
            currency="USDT",
            network="TRC20",
            asset_type="token",
            decimals=6,
            min_confirmations=20,
            is_enabled=False,
        )
        session.add(asset)
        session.flush()
        for source, symbol, base, quote in (
            ("coinbase", "USDT-USD", "USDT", "USD"),
            ("kraken", "USDTUSD", "USDT", "USD"),
            ("bitstamp", "usdtusd", "USDT", "USD"),
        ):
            session.add(ExchangeMarketMapping(
                payment_asset_id=asset.id,
                source=source,
                market_symbol=symbol,
                market_base_currency=base,
                market_quote_currency=quote,
                is_enabled=True,
                reviewed_at=NOW,
            ))
        session.commit()
        yield session, asset
    engine.dispose()


def test_loads_only_three_explicit_enabled_source_mappings(db):
    session, asset = db
    specs = load_enabled_market_specs(
        session,
        payment_asset_id=asset.id,
        payment_currency="USDT",
    )
    assert {item.source for item in specs} == {"coinbase", "kraken", "bitstamp"}
    assert {item.market_symbol for item in specs} == {"USDT-USD", "USDTUSD", "usdtusd"}


def test_missing_source_mapping_fails_closed(db):
    session, asset = db
    row = session.query(ExchangeMarketMapping).filter_by(source="bitstamp").one()
    row.is_enabled = False
    session.commit()
    with pytest.raises(ValueError, match="exactly one enabled"):
        load_enabled_market_specs(session, payment_asset_id=asset.id, payment_currency="USDT")


def test_wrong_or_cross_market_pair_fails_closed(db):
    session, asset = db
    row = session.query(ExchangeMarketMapping).filter_by(source="kraken").one()
    row.market_base_currency = "BTC"
    row.market_quote_currency = "USDT"
    session.commit()
    with pytest.raises(ValueError, match="direct spot pair"):
        load_enabled_market_specs(session, payment_asset_id=asset.id, payment_currency="USDT")


def test_usd_per_token_market_is_inverted_to_token_per_usd():
    assert normalize_market_midpoint(
        Decimal("2"),
        market_base_currency="USDT",
        market_quote_currency="USD",
        payment_currency="USDT",
    ) == Decimal("0.5")


def test_token_per_usd_market_is_kept_as_payment_units_per_usd():
    assert normalize_market_midpoint(
        Decimal("2"),
        market_base_currency="USD",
        market_quote_currency="USDT",
        payment_currency="USDT",
    ) == Decimal("2")


def test_normalization_rejects_invalid_midpoint_and_non_usd_cross():
    with pytest.raises(ValueError, match="positive"):
        normalize_market_midpoint(
            Decimal("0"),
            market_base_currency="USDT",
            market_quote_currency="USD",
            payment_currency="USDT",
        )
    with pytest.raises(ValueError, match="directly"):
        normalize_market_midpoint(
            Decimal("2"),
            market_base_currency="BTC",
            market_quote_currency="USDT",
            payment_currency="USDT",
        )


def test_fetcher_normalizes_each_exchange_using_its_own_market_orientation(monkeypatch):
    import asyncio
    import app.market_mappings as module

    async def fake_fetch(**kwargs):
        assert kwargs["coinbase_product_id"] == "USDT-USD"
        assert kwargs["kraken_pair"] == "USDUSDT"
        assert kwargs["bitstamp_market_symbol"] == "usdtusd"
        return [
            RateObservation("coinbase", Decimal("2"), NOW),
            RateObservation("kraken", Decimal("2"), NOW),
            RateObservation("bitstamp", Decimal("2"), NOW),
        ]

    monkeypatch.setattr(module, "fetch_three_exchange_observations", fake_fetch)
    mappings = (
        ExchangeMarketSpec("coinbase", "USDT-USD", "USDT", "USD"),
        ExchangeMarketSpec("kraken", "USDUSDT", "USD", "USDT"),
        ExchangeMarketSpec("bitstamp", "usdtusd", "USDT", "USD"),
    )
    result = asyncio.run(fetch_payment_asset_observations(
        payment_currency="USDT",
        mappings=mappings,
        now=NOW,
    ))
    assert [row.units_per_usd for row in result] == [
        Decimal("0.5"),
        Decimal("2"),
        Decimal("0.5"),
    ]



def test_database_rejects_enabled_mapping_without_review_timestamp(db):
    session, asset = db
    session.add(ExchangeMarketMapping(
        payment_asset_id=asset.id,
        source="coinbase",
        market_symbol="USDT-USD",
        market_base_currency="USDT",
        market_quote_currency="USD",
        is_enabled=True,
        reviewed_at=None,
    ))
    with pytest.raises(IntegrityError):
        session.commit()
    session.rollback()
