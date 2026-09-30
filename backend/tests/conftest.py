"""Database fixtures: a dedicated *_test database, built by running the real Alembic migration."""

import os
from collections.abc import Iterator

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, make_url, text
from sqlalchemy.orm import Session

DEFAULT_TEST_URL = "postgresql+psycopg://vulnscope:vulnscope@localhost:5432/vulnscope_test"


def _test_url() -> str:
    url = os.environ.get("TEST_DATABASE_URL", DEFAULT_TEST_URL)
    # The fixture drops the whole schema; never let it point at a real database.
    if not (make_url(url).database or "").endswith("_test"):
        raise RuntimeError(f"TEST_DATABASE_URL must name a *_test database, got {url!r}")
    return url


def _ensure_database(url: str) -> None:
    """Create the test database if it doesn't exist (connects to the `postgres` maintenance DB)."""
    parsed = make_url(url)
    admin = create_engine(parsed.set(database="postgres"), isolation_level="AUTOCOMMIT")
    try:
        with admin.connect() as conn:
            exists = conn.scalar(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": parsed.database}
            )
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{parsed.database}"'))
    finally:
        admin.dispose()


def alembic_config(url: str) -> Config:
    cfg = Config(os.path.join(os.path.dirname(__file__), "..", "alembic.ini"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


@pytest.fixture(scope="session")
def db_url() -> str:
    return _test_url()


@pytest.fixture(scope="session")
def engine(db_url: str) -> Iterator[Engine]:
    _ensure_database(db_url)
    eng = create_engine(db_url)
    with eng.begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
    command.upgrade(alembic_config(db_url), "head")
    yield eng
    eng.dispose()


@pytest.fixture
def db(engine: Engine) -> Iterator[Session]:
    """A session whose work is rolled back after each test, even if the test commits."""
    with engine.connect() as conn:
        outer = conn.begin()
        session = Session(bind=conn, join_transaction_mode="create_savepoint")
        try:
            yield session
        finally:
            session.close()
            outer.rollback()
