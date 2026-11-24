"""Every test runs against its own data directory, never the address lists or reads in ~/.sg-tightener: a list
downloaded there (by install.sh or a real run) must not change what a test sees.

Everything the tool keeps is in PostgreSQL (sg_store). Tests use their own database, ``sgtightener_test`` on
the server ``sg_store.py setup`` started (or ``$SG_TIGHTENER_TEST_PG_DSN``), never the real one: each data
directory and each sg.db location a test uses is a schema of its own there, dropped when the run ends. With no
PostgreSQL to reach the run stops and says so, rather than skipping what it cannot test."""

from __future__ import annotations

import os

import pytest

import sg_ipintel
import sg_store

TEST_DB = "sgtightener_test"


def _test_dsn() -> str:
    given = os.environ.get("SG_TIGHTENER_TEST_PG_DSN", "").strip()
    if given:
        return given
    import psycopg
    from psycopg.conninfo import conninfo_to_dict, make_conninfo

    try:
        base = sg_store.dsn()
    except sg_store.NotConfigured as exc:
        pytest.exit(f"the tests need PostgreSQL: {exc} (or set SG_TIGHTENER_TEST_PG_DSN)", returncode=2)
    with psycopg.connect(base, autocommit=True, connect_timeout=10) as con:
        if not con.execute("SELECT 1 FROM pg_database WHERE datname = %s", (TEST_DB,)).fetchone():
            con.execute(f"CREATE DATABASE {TEST_DB}")
    return make_conninfo(**{**conninfo_to_dict(base), "dbname": TEST_DB})


def _drop_test_schemas(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as con:
        for (name,) in con.execute("SELECT nspname FROM pg_namespace WHERE nspname LIKE 't\\_%' OR nspname = 'tests'").fetchall():
            con.execute(f'DROP SCHEMA "{name}" CASCADE')


@pytest.fixture(autouse=True, scope="session")
def _own_database():
    dsn = _test_dsn()
    old = {k: os.environ.get(k) for k in (sg_store.DSN_ENV, sg_store.SCHEMA_ENV)}
    os.environ[sg_store.DSN_ENV] = dsn
    os.environ[sg_store.SCHEMA_ENV] = "tests"  # the ~/.sg-tightener schema, should a test reach it
    try:
        _drop_test_schemas(dsn)
    except Exception as exc:  # noqa: BLE001
        pytest.exit(f"the tests need PostgreSQL and {dsn.split('@')[-1]} does not answer: {exc}", returncode=2)
    yield
    _drop_test_schemas(dsn)
    for k, v in old.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


@pytest.fixture(autouse=True, scope="session")
def _own_data_dir(_own_database, tmp_path_factory):
    old = sg_ipintel.DATA_DIR
    sg_ipintel.set_data_dir(tmp_path_factory.mktemp("sg-data"))
    yield
    sg_ipintel.set_data_dir(old)
