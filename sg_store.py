#!/usr/bin/env python3
"""sg_store.py: where sg-tightener keeps everything, in one PostgreSQL database.

Every tool keeps its state here: the security group database and its audit trail (sg_db), each account's
flow-log reads (sg_review), the console's report rows, account owners and sign-ins, the IP intelligence
lists, watch and Security Hub state. Only what you hand between commands (plan.json, approved.json,
manifests, report pages) and what you edit yourself (names.yaml) stay files.

**Freeze at fetch.** A flow-log slice is read from CloudWatch once and never read again: flow logs reach
CloudWatch within about ten minutes, and a read stops a quarter of an hour short of now (sg_review.LAG), so a
slice that has been read is complete. Only the open tail slices of ``watch`` are replaced, by the hourly read.

**Kept 12 months.** Flow-log slices that end more than ``RETENTION_DAYS`` ago, and the read log, are deleted
on every save and by ``prune``. The audit trail and change requests are never deleted: the trail is
hash-chained and append-only, and removing its head would break ``sg_db.py verify``.

Where the database is: ``$SG_TIGHTENER_PG_DSN``, else ``~/.sg-tightener/pg.dsn`` (written by ``setup``).
Each data directory is its own schema: ``~/.sg-tightener`` is ``sgt`` (or ``$SG_TIGHTENER_PG_SCHEMA``), any
other (``--data-dir``, tests) ``t_<hash of its path>``, so a second data directory never sees the first's data.

Usage:
  sg_store.py setup  [--port 55432]     start PostgreSQL in Docker on 127.0.0.1, save how to reach it, create tables
  sg_store.py start                     start it again (and colima first, when Docker's engine is not running);
                                        the console's "Start the database" button does the same
  sg_store.py migrate [--keep]          copy ~/.sg-tightener's files (sg.db, reads, caches) into the database,
                                        then move them to ~/.sg-tightener/migrated-<time>/ (--keep leaves them)
  sg_store.py status                    where the database is and what it holds
  sg_store.py prune                     delete flow-log data older than 12 months now
  sg_store.py backup [--dir D] [--keep 14]   pg_dump the whole database to ~/.sg-tightener/backups/ (0600),
                                        check the file reads back, keep the newest 14
  sg_store.py restore FILE --yes        put a backup back, replacing what the database holds now
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from functools import lru_cache
from pathlib import Path

DSN_ENV = "SG_TIGHTENER_PG_DSN"
SCHEMA_ENV = "SG_TIGHTENER_PG_SCHEMA"
DEFAULT_SCHEMA = "sgt"
DEFAULT_PORT = 55432
RETENTION_DAYS = 365
RETENTION = RETENTION_DAYS * 86400
_SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class NotConfigured(RuntimeError):
    """No database has been set up."""


def home_dir() -> Path:
    return Path.home() / ".sg-tightener"


def dsn_file() -> Path:
    return home_dir() / "pg.dsn"


def dsn() -> str:
    v = os.environ.get(DSN_ENV, "").strip()
    if not v:
        try:
            v = dsn_file().read_text().strip()
        except OSError:
            v = ""
    if not v:
        raise NotConfigured("sg-tightener keeps its data in PostgreSQL and none is set up: run "
                            "`python3 sg_store.py setup` (or set SG_TIGHTENER_PG_DSN)")  # fmt: skip
    return v


# ------------------------------------------------------------------------------------------- schemas
def schema_for_dir(d) -> str:
    """The schema that holds one data directory's data."""
    d = Path(d).expanduser().resolve()
    if d == home_dir().resolve():
        s = os.environ.get(SCHEMA_ENV, "").strip() or DEFAULT_SCHEMA
        if not _SCHEMA_RE.fullmatch(s):
            raise ValueError(f"{SCHEMA_ENV} must be lower-case letters, digits and _: {s!r}")
        return s
    return "t_" + hashlib.sha1(str(d).encode()).hexdigest()[:16]


def data_schema() -> str:
    """The schema of the data directory in use (sg_ipintel.DATA_DIR)."""
    import sg_ipintel

    return schema_for_dir(sg_ipintel.DATA_DIR)


def locate(path) -> tuple[str, str]:
    """(schema, key) of what used to be a file: its path inside the data directory in use, or its name inside
    a schema of its own folder."""
    import sg_ipintel

    p = Path(path).expanduser().resolve()
    root = Path(sg_ipintel.DATA_DIR).expanduser().resolve()
    try:
        return schema_for_dir(root), p.relative_to(root).as_posix()
    except ValueError:
        return schema_for_dir(p.parent), p.name


# ------------------------------------------------------------------------------------------- tables
DDL = r"""
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS regions (
  account TEXT NOT NULL, region TEXT NOT NULL, imported_at TEXT NOT NULL, synced_at TEXT NOT NULL,
  PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS groups (
  account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '', vpc_id TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, region, group_id));
CREATE TABLE IF NOT EXISTS rules (
  account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('desired', 'synced')),
  direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  proto TEXT NOT NULL, from_port INTEGER NOT NULL, to_port INTEGER NOT NULL, source TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, region, group_id, state, direction, proto, from_port, to_port, source));
CREATE TABLE IF NOT EXISTS audit (
  seq BIGSERIAL PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL, origin TEXT NOT NULL,
  action TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  detail TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', ticket TEXT NOT NULL DEFAULT '',
  prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_group ON audit (account, region, group_id);
CREATE TABLE IF NOT EXISTS accounts (account TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS requests (
  id BIGSERIAL PRIMARY KEY, at TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
  proposer TEXT NOT NULL, reason TEXT NOT NULL, ticket TEXT NOT NULL DEFAULT '', changes TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'applied')),
  decided_by TEXT NOT NULL DEFAULT '', decided_at TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS requests_status ON requests (status, account, region);
CREATE TABLE IF NOT EXISTS modes (
  account TEXT PRIMARY KEY, mode TEXT NOT NULL CHECK (mode IN ('surveillance', 'enforce')),
  set_by TEXT NOT NULL, set_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions (
  account TEXT NOT NULL, region TEXT NOT NULL, checked_at TEXT NOT NULL, actor TEXT NOT NULL,
  ok INTEGER NOT NULL, result TEXT NOT NULL, PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS assets (
  account TEXT NOT NULL, region TEXT NOT NULL, eni TEXT NOT NULL, instance TEXT NOT NULL DEFAULT '',
  asg TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', vpc_id TEXT NOT NULL DEFAULT '',
  ips TEXT NOT NULL DEFAULT '[]', groups TEXT NOT NULL DEFAULT '[]', description TEXT NOT NULL DEFAULT '',
  observed_at TEXT NOT NULL, PRIMARY KEY (account, region, eni));
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
  BEGIN RAISE EXCEPTION 'the audit trail is append-only'; END $$;
DROP TRIGGER IF EXISTS audit_append_only_u ON audit;
CREATE TRIGGER audit_append_only_u BEFORE UPDATE ON audit FOR EACH ROW EXECUTE FUNCTION audit_append_only();
DROP TRIGGER IF EXISTS audit_append_only_d ON audit;
CREATE TRIGGER audit_append_only_d BEFORE DELETE ON audit FOR EACH ROW EXECUTE FUNCTION audit_append_only();
DROP TRIGGER IF EXISTS audit_append_only_t ON audit;
CREATE TRIGGER audit_append_only_t BEFORE TRUNCATE ON audit FOR EACH STATEMENT EXECUTE FUNCTION audit_append_only();

CREATE TABLE IF NOT EXISTS review_accounts (
  account TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '', mode TEXT NOT NULL DEFAULT 'live',
  meta JSONB NOT NULL DEFAULT '{}', updated_at DOUBLE PRECISION NOT NULL);
CREATE TABLE IF NOT EXISTS review_regions (
  account TEXT NOT NULL REFERENCES review_accounts ON DELETE CASCADE, region TEXT NOT NULL,
  data JSONB NOT NULL, PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS review_slices (
  id BIGSERIAL PRIMARY KEY, account TEXT NOT NULL REFERENCES review_accounts ON DELETE CASCADE,
  region TEXT NOT NULL, s BIGINT NOT NULL, e BIGINT NOT NULL, data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS review_slices_account ON review_slices (account, region, s);
CREATE INDEX IF NOT EXISTS review_slices_end ON review_slices (e);
CREATE TABLE IF NOT EXISTS review_reads (
  id BIGSERIAL PRIMARY KEY, account TEXT NOT NULL REFERENCES review_accounts ON DELETE CASCADE,
  at DOUBLE PRECISION NOT NULL, data JSONB NOT NULL);
CREATE INDEX IF NOT EXISTS review_reads_account ON review_reads (account, at);

CREATE TABLE IF NOT EXISTS report_rows (
  kind TEXT NOT NULL, range_key TEXT NOT NULL, account TEXT NOT NULL, version INTEGER NOT NULL,
  stamp DOUBLE PRECISION NOT NULL, at DOUBLE PRECISION NOT NULL, row JSONB,
  PRIMARY KEY (kind, range_key, account));
CREATE TABLE IF NOT EXISTS files (key TEXT PRIMARY KEY, data BYTEA NOT NULL, updated_at DOUBLE PRECISION NOT NULL);
"""


# ------------------------------------------------------------------------------------------- connections
def _psycopg():
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - said plainly rather than as a traceback
        raise NotConfigured("the PostgreSQL driver is not installed: pip install -r requirements.txt") from exc
    return psycopg


@lru_cache(maxsize=512)
def translate(sql: str, named: bool) -> str:
    """SQLite-style SQL (``?`` and ``:name`` parameters) as psycopg's (``%s``, ``%(name)s``, ``%%``)."""
    out, i, n, quoted = [], 0, len(sql), False
    while i < n:
        ch = sql[i]
        if ch == "'":
            quoted = not quoted
            out.append(ch)
        elif ch == "%":
            out.append("%%")
        elif not quoted and ch == "?" and not named:
            out.append("%s")
        elif (not quoted and named and ch == ":" and i + 1 < n and (sql[i + 1].isalpha() or sql[i + 1] == "_")
              and (i == 0 or sql[i - 1] != ":")):  # fmt: skip
            j = i + 1
            while j < n and (sql[j].isalnum() or sql[j] == "_"):
                j += 1
            out.append(f"%({sql[i + 1:j]})s")
            i = j
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


_ready: set = set()
_ready_lock = threading.Lock()


def _ensure(conn, schema: str) -> None:
    key = (os.getpid(), conn.info.dsn, schema)
    with _ready_lock:
        if key in _ready:
            return
    with conn.transaction():  # one creator at a time, across processes
        conn.execute("SELECT pg_advisory_xact_lock(hashtext('sg-tightener-ddl'))")
        conn.execute(f'CREATE SCHEMA IF NOT EXISTS "{schema}"')
        conn.execute(f'SET LOCAL search_path TO "{schema}"')
        conn.execute(DDL)
    with _ready_lock:
        _ready.add(key)


class Db:
    """One connection with SQLite-style parameters. Autocommit; ``transaction()`` groups statements."""

    def __init__(self, schema: str, conninfo: str | None = None):
        if not _SCHEMA_RE.fullmatch(schema):
            raise ValueError(f"not a schema name: {schema!r}")
        self.schema, self.conninfo = schema, conninfo or dsn()
        self.conn = None
        self._open()

    def _open(self) -> None:
        psycopg = _psycopg()
        try:
            self.conn = psycopg.connect(self.conninfo, autocommit=True, connect_timeout=10,
                                        application_name="sg-tightener")  # fmt: skip
        except psycopg.OperationalError as exc:
            raise NotConfigured(f"cannot reach the sg-tightener database ({str(exc).strip()[:200]}): is it running? "
                                "Start it with the console's Start the database button or `python3 sg_store.py start` "
                                "(first time: `python3 sg_store.py setup`)") from exc  # fmt: skip
        _ensure(self.conn, self.schema)
        self.conn.execute(f'SET search_path TO "{self.schema}"')

    @property
    def idle(self) -> bool:
        return self.conn.info.transaction_status == _psycopg().pq.TransactionStatus.IDLE

    def execute(self, sql: str, params=None):
        q = sql if params is None else translate(sql, isinstance(params, dict))
        try:
            return self.conn.execute(q, params)
        except _psycopg().OperationalError:
            if not self.conn.closed:
                raise
            self._open()  # the server restarted: one more try on a new connection (never inside a transaction)
            return self.conn.execute(q, params)

    def executemany(self, sql: str, seq) -> None:
        seq = list(seq)
        if seq:
            with self.conn.cursor() as cur:
                cur.executemany(translate(sql, isinstance(seq[0], dict)), seq)

    def transaction(self):
        if self.conn.closed:
            self._open()
        return self.conn.transaction()

    def close(self) -> None:
        if self.conn is not None:
            self.conn.close()


_local = threading.local()


def db(schema: str | None = None) -> Db:
    """This thread's connection to ``schema`` (the data directory's by default)."""
    schema = schema or data_schema()
    conns = getattr(_local, "conns", None)
    if conns is None or getattr(_local, "pid", None) != os.getpid():
        conns = _local.conns = {}
        _local.pid = os.getpid()
    key = (dsn(), schema)
    got = conns.get(key)
    if got is None or got.conn.closed:
        got = conns[key] = Db(schema, key[0])
    return got


def _jsonb(v):
    from psycopg.types.json import Jsonb

    return Jsonb(v, dumps=_dumps)


def _dumps(v) -> str:
    return json.dumps(v, separators=(",", ":"))


# ------------------------------------------------------------------------------------------- files
class File:
    """What used to be a small file under the data directory (a cache, a sign-in, a token), kept in the
    database under its path. ``read_*`` raise FileNotFoundError when it was never written."""

    def __init__(self, path):
        self.path = path.path if isinstance(path, File) else Path(path)
        self.schema, self.key = locate(self.path)

    def _row(self):
        return db(self.schema).execute("SELECT data, updated_at FROM files WHERE key = ?", (self.key,)).fetchone()

    def read_bytes(self) -> bytes:
        row = self._row()
        if row is None:
            raise FileNotFoundError(self.key)
        return bytes(row[0])

    def read_text(self) -> str:
        return self.read_bytes().decode("utf-8")

    def write_bytes(self, data: bytes) -> None:
        db(self.schema).execute("INSERT INTO files (key, data, updated_at) VALUES (?, ?, ?) ON CONFLICT (key) DO UPDATE "
                                "SET data = excluded.data, updated_at = excluded.updated_at",
                                (self.key, bytes(data), time.time()))  # fmt: skip

    def write_text(self, text: str) -> None:
        self.write_bytes(text.encode("utf-8"))

    def stamp(self) -> float | None:
        """When it was last written (the old mtime), or None."""
        row = db(self.schema).execute("SELECT updated_at FROM files WHERE key = ?", (self.key,)).fetchone()
        return row[0] if row else None

    def exists(self) -> bool:
        return self.stamp() is not None

    def unlink(self) -> bool:
        return db(self.schema).execute("DELETE FROM files WHERE key = ?", (self.key,)).rowcount > 0


def stamps(paths) -> dict:
    """{path: when last written or None} for several files of one data directory, in one query."""
    files = [File(p) for p in paths]
    by_schema: dict = {}
    for f in files:
        by_schema.setdefault(f.schema, []).append(f.key)
    got = {}
    for schema, keys in by_schema.items():
        for k, at in db(schema).execute("SELECT key, updated_at FROM files WHERE key = ANY(?)", (keys,)):
            got[(schema, k)] = at
    return {f.path: got.get((f.schema, f.key)) for f in files}


# ------------------------------------------------------------------------------------------- flow-log reads
_region_hash: dict = {}


def review_accounts(schema: str | None = None) -> list[str]:
    return [r[0] for r in db(schema).execute("SELECT account FROM review_accounts ORDER BY account")]


def review_stamps(schema: str | None = None) -> dict[str, float]:
    """{account: when its read was last saved}."""
    return dict(db(schema).execute("SELECT account, updated_at FROM review_accounts"))


def review_stamp(account: str, schema: str | None = None) -> float | None:
    row = db(schema).execute("SELECT updated_at FROM review_accounts WHERE account = ?", (account,)).fetchone()
    return row[0] if row else None


def _stream(d, sql: str, params) -> Iterable:
    """Rows of a big query a few at a time (a server-side cursor), so the whole result is never held twice:
    once as text from the server and once as Python objects. Inside a transaction only."""
    cur = d.conn.cursor(name=f"sgt_{os.getpid()}_{threading.get_ident()}")
    cur.itersize = 20
    try:
        cur.execute(translate(sql, False), params)
        yield from cur
    finally:
        cur.close()


def _share(rows, seen: dict) -> None:
    """Make every repeated value in flow-log rows one shared object. An account's rows repeat the same few
    thousand addresses, interfaces and ports millions of times; as separate strings and numbers they took
    6.4 GB for the busiest account (14.7 million rows); shared, and read a few slices at a time, 2.2 GB."""
    if not rows:
        return
    get = seen.setdefault
    for r in rows:
        if len(r) == 7:  # source, destination, interface, protocol, port, action, flows (flows are mostly small)
            a, b, c, p, q, x = r[0], r[1], r[2], r[3], r[4], r[5]
            r[0], r[1], r[2], r[3], r[4], r[5] = get(a, a), get(b, b), get(c, c), get(p, p), get(q, q), get(x, x)
        else:
            for i, v in enumerate(r):
                if v.__class__ is str or v.__class__ is int:
                    r[i] = get(v, v)


def review_load(account: str, schema: str | None = None, doc_schema: int = 1, rows: bool = True) -> dict | None:
    """An account's read. Without ``rows`` each slice comes without its flow-log rows (what was read, when, and
    its state only): a fraction of the memory, for reports that need no traffic."""
    d = db(schema)
    cutoff = time.time() - RETENTION
    seen: dict = {}
    with d.transaction():  # one consistent picture while a read is saving
        row = d.execute("SELECT name, mode, meta FROM review_accounts WHERE account = ?", (account,)).fetchone()
        if row is None:
            return None
        regions = dict(d.execute("SELECT region, data FROM review_regions WHERE account = ?", (account,)))
        chunks = []
        cols = "data" if rows else "data - 'rows' - 'pub'"
        sql = f"SELECT id, {cols} FROM review_slices WHERE account = ? AND e >= ? ORDER BY id"
        for k, data in _stream(d, sql, (account, cutoff)) if rows else d.execute(sql, (account, cutoff)):
            data["k"] = k
            if rows:
                _share(data.get("rows"), seen)
            chunks.append(data)
        reads = []
        for k, data in d.execute("SELECT id, data FROM review_reads WHERE account = ? AND at >= ? ORDER BY id",
                                 (account, cutoff)):  # fmt: skip
            data["k"] = k
            reads.append(data)
    for region, data in regions.items():
        _region_hash[(os.getpid(), d.schema, account, region)] = _digest(data)
    meta = row[2] or {}
    return {**meta, "schema": doc_schema, "account": account, "name": row[0], "mode": row[1], "regions": regions,
            "chunks": chunks, "reads": reads}  # fmt: skip


def _digest(v) -> str:
    return hashlib.sha1(_dumps(v).encode()).hexdigest()


def review_save(doc: dict, schema: str | None = None) -> None:
    """Save a read: the account, each region that changed, the slices not saved before (each is given its row
    id as "k"); slices and reads no longer in ``doc``, or older than 12 months, are deleted."""
    d = db(schema)
    account, now = doc["account"], time.time()
    cutoff = now - RETENTION
    doc["chunks"][:] = [c for c in doc["chunks"] if c.get("e", now) >= cutoff]
    doc["reads"][:] = [r for r in doc.get("reads") or [] if r.get("at", now) >= cutoff]
    meta = {k: v for k, v in doc.items() if k not in ("schema", "account", "name", "mode", "regions", "chunks", "reads")}
    with d.transaction():
        d.execute("INSERT INTO review_accounts (account, name, mode, meta, updated_at) VALUES (?, ?, ?, ?, ?) "
                  "ON CONFLICT (account) DO UPDATE SET name = excluded.name, mode = excluded.mode, meta = excluded.meta, "
                  "updated_at = excluded.updated_at",
                  (account, doc.get("name") or "", doc.get("mode") or "live", _jsonb(meta), now))  # fmt: skip
        have = {r[0] for r in d.execute("SELECT region FROM review_regions WHERE account = ?", (account,))}
        for region, data in doc["regions"].items():
            key, h = (os.getpid(), d.schema, account, region), _digest(data)
            if region in have and _region_hash.get(key) == h:
                continue
            d.execute("INSERT INTO review_regions (account, region, data) VALUES (?, ?, ?) ON CONFLICT (account, region) "
                      "DO UPDATE SET data = excluded.data", (account, region, _jsonb(data)))  # fmt: skip
            _region_hash[key] = h
        gone = sorted(have - set(doc["regions"]))
        if gone:
            d.execute("DELETE FROM review_regions WHERE account = ? AND region = ANY(?)", (account, gone))
        _sync_rows(d, "review_slices", account, doc["chunks"],
                   lambda c: (c.get("r") or "", int(c.get("s") or 0), int(c.get("e") or 0)), "region, s, e")
        _sync_rows(d, "review_reads", account, doc["reads"], lambda r: (float(r.get("at") or 0),), "at")
        d.execute("DELETE FROM review_slices WHERE account = ? AND e < ?", (account, cutoff))
        d.execute("DELETE FROM review_reads WHERE account = ? AND at < ?", (account, cutoff))


def _sync_rows(d: Db, table: str, account: str, items: list[dict], cols, names: str) -> None:
    have = {r[0] for r in d.execute(f"SELECT id FROM {table} WHERE account = ?", (account,))}  # noqa: S608
    keep = {it["k"] for it in items if it.get("k") in have}
    gone = sorted(have - keep)
    if gone:
        d.execute(f"DELETE FROM {table} WHERE id = ANY(?)", (gone,))  # noqa: S608
    marks = ", ".join("?" for _ in names.split(","))
    sql = translate(f"INSERT INTO {table} (account, {names}, data) VALUES (?, {marks}, ?) RETURNING id", False)  # noqa: S608
    for it in items:
        if it.get("k") in keep:
            continue
        body = {k: v for k, v in it.items() if k != "k"}
        it["k"] = d.conn.execute(sql, (account, *cols(it), _jsonb(body))).fetchone()[0]


def review_forget(account: str, schema: str | None = None) -> bool:
    return db(schema).execute("DELETE FROM review_accounts WHERE account = ?", (account,)).rowcount > 0


def prune(schema: str | None = None, now: float | None = None) -> dict:
    """Delete flow-log data older than 12 months; the audit trail is never deleted."""
    cutoff = (now or time.time()) - RETENTION
    d = db(schema)
    with d.transaction():
        s = d.execute("DELETE FROM review_slices WHERE e < ?", (cutoff,)).rowcount
        r = d.execute("DELETE FROM review_reads WHERE at < ?", (cutoff,)).rowcount
    return {"slices": s, "reads": r}


# ------------------------------------------------------------------------------------------- report rows
def report_rows(version, schema: str | None = None) -> dict:
    """{"kind|range|account": {"mtime", "at", "row"}}. A row an earlier version of the reports built is kept, marked
    ``old`` with no stamp, so it is shown until this version rebuilds it rather than the page going empty after an
    upgrade. ``version`` is a number, or a function of the kind giving the version that kind needs: a row at that
    version or later is current, so a bump for one kind rebuilds that kind only."""
    need = version if callable(version) else (lambda _k: version)
    return {f"{k}|{r}|{a}": ({"mtime": st, "at": at, "row": row} if v >= need(k) else
                             {"mtime": None, "at": at, "row": row, "old": True})
            for k, r, a, v, st, at, row in db(schema).execute(
                "SELECT kind, range_key, account, version, stamp, at, row FROM report_rows")}


def save_report_rows(version, rows: dict, schema: str | None = None) -> None:
    need = version if callable(version) else (lambda _k: version)
    d = db(schema)
    with d.transaction():
        d.executemany("INSERT INTO report_rows (kind, range_key, account, version, stamp, at, row) VALUES "
                      "(?, ?, ?, ?, ?, ?, ?) ON CONFLICT (kind, range_key, account) DO UPDATE SET version = excluded.version, "
                      "stamp = excluded.stamp, at = excluded.at, row = excluded.row",
                      [(*k.split("|", 2), need(k.split("|", 1)[0]), v["mtime"], v["at"], _jsonb(v["row"]))
                       for k, v in rows.items()])  # fmt: skip


# ------------------------------------------------------------------------------------------- the local server
COMPOSE_YML = """# sg-tightener's database: PostgreSQL on this machine only (127.0.0.1), data in the named volume.
# Written by sg_store.py (setup, start, and the console's Start the database button); edits are overwritten.
# The password is in pg.env beside it (0600), how to connect in ../pg.dsn (0600).
name: sg-tightener
services:
  postgres:
    image: postgres:17.6-alpine
    restart: unless-stopped
    environment:
      POSTGRES_USER: sgt
      POSTGRES_DB: sgtightener
      POSTGRES_PASSWORD: ${SGT_PG_PASSWORD:?run sg_store.py setup}
    command: ["postgres", "-c", "max_connections=300", "-c", "shared_buffers=256MB",
              "-c", "default_toast_compression=lz4"]
    ports:
      - "127.0.0.1:${SGT_PG_PORT:-55432}:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U sgt -d sgtightener"]
      interval: 5s
      timeout: 3s
      retries: 20
volumes:
  pgdata:
    name: sg-tightener-pgdata
"""
START_TIMEOUT = 600  # colima's first start downloads a virtual machine image


def compose_file() -> Path:
    """The compose file of the local server, written out from COMPOSE_YML (so the copy the console runs from,
    which has no deploy folder, can start it too)."""
    path = home_dir() / "postgres" / "compose.yml"
    if not path.exists() or path.read_text() != COMPOSE_YML:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(COMPOSE_YML)
    return path


def env_file() -> Path:
    return home_dir() / "pg.env"


def _bin(name: str) -> str | None:
    """A program, also where Homebrew puts it: a background service's PATH may not include it."""
    return shutil.which(name) or next((str(p) for p in (Path("/opt/homebrew/bin") / name, Path("/usr/local/bin") / name)
                                       if p.exists()), None)  # fmt: skip


def _run(cmd: list, timeout: float = 120) -> subprocess.CompletedProcess:
    env = {**os.environ, "PATH": os.pathsep.join([os.environ.get("PATH", ""), "/opt/homebrew/bin", "/usr/local/bin"])}
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


def reachable() -> tuple[bool, str]:
    """(the database answers, why not)."""
    try:
        conninfo = dsn()
    except NotConfigured as exc:
        return False, str(exc)
    try:
        import psycopg

        psycopg.connect(conninfo, connect_timeout=3).close()
        return True, ""
    except Exception as exc:  # noqa: BLE001 - said on the page
        return False, str(exc).strip().splitlines()[0][:300] if str(exc).strip() else type(exc).__name__


def server_status() -> dict:
    """What the console's database banner shows: does the database answer, and can this machine start it."""
    ok, why = reachable()
    docker, colima = _bin("docker"), _bin("colima")
    local = env_file().exists()
    engine = None
    if not ok and docker:
        try:
            engine = _run([docker, "info", "--format", "{{.ServerVersion}}"], 20).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            engine = False
    return {"ok": ok, "why": why, "local": local, "docker": bool(docker), "colima": bool(colima), "engine": engine,
            "can_start": not ok and local and bool(docker) and (engine or bool(colima))}  # fmt: skip


def start_server(say=print) -> None:
    """Start the local database: colima first when Docker's engine is not running, then the container. Raises
    RuntimeError saying what failed."""
    if reachable()[0]:
        say("the database is already running")
        return
    if not env_file().exists():
        raise RuntimeError("no local database was set up on this computer: run `python3 sg_store.py setup`")
    docker = _bin("docker")
    if not docker:
        raise RuntimeError("Docker is not installed (brew install colima docker docker-compose)")
    if _run([docker, "info"], 20).returncode != 0:
        colima = _bin("colima")
        if not colima:
            raise RuntimeError("Docker's engine is not running, and colima is not installed to start it: start Docker")
        say("starting colima (Docker's engine) ...")
        r = _run([colima, "start"], START_TIMEOUT)
        if r.returncode != 0:
            raise RuntimeError(f"colima did not start: {(r.stderr or r.stdout).strip()[-400:]}")
    say("starting the database container ...")
    r = _run([docker, "compose", "-f", str(compose_file()), "--env-file", str(env_file()), "up", "-d", "--wait"],
             START_TIMEOUT)  # fmt: skip
    if r.returncode != 0:
        raise RuntimeError(f"the database container did not start: {(r.stderr or r.stdout).strip()[-400:]}")
    for _ in range(60):
        if reachable()[0]:
            say("the database is running")
            return
        time.sleep(1)
    raise RuntimeError(f"the container started but the database does not answer: {reachable()[1]}")


# ------------------------------------------------------------------------------------------- setup and migrate


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def cmd_setup(args) -> int:
    if not _bin("docker"):
        print("Docker is not installed. Install Docker (or colima: brew install colima docker docker-compose), "
              "or set SG_TIGHTENER_PG_DSN to a PostgreSQL you already run.", file=sys.stderr)  # fmt: skip
        return 2
    pw = ""
    try:
        pw = dict(line.split("=", 1) for line in env_file().read_text().split() if "=" in line).get("SGT_PG_PASSWORD", "")
    except OSError:
        pass
    pw = pw or secrets.token_urlsafe(24)
    _write_private(env_file(), f"SGT_PG_PASSWORD={pw}\nSGT_PG_PORT={args.port}\n")
    conninfo = f"postgresql://sgt:{pw}@127.0.0.1:{args.port}/sgtightener"
    _write_private(dsn_file(), conninfo + "\n")
    os.environ.setdefault(DSN_ENV, conninfo)
    try:
        start_server()
        Db(schema_for_dir(home_dir()), conninfo).close()
    except (RuntimeError, NotConfigured) as exc:
        print(exc, file=sys.stderr)
        return 1
    print(f"ready: {dsn_file()} (0600) says how to reach it; tables are in schema {schema_for_dir(home_dir())}")
    print("next: python3 sg_store.py migrate   (copies sg.db and the reads already on disk)")
    return 0


def cmd_start(_args) -> int:
    try:
        start_server()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


def _sqlite_rows(path: Path, table: str) -> tuple[list[str], list[tuple]]:
    import sqlite3

    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        if not con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone():
            return [], []
        cur = con.execute(f"SELECT * FROM {table}")  # noqa: S608 - table names are ours
        return [c[0] for c in cur.description], cur.fetchall()
    finally:
        con.close()


SQLITE_TABLES = ("meta", "regions", "groups", "rules", "accounts", "requests", "modes", "permissions", "assets", "audit")


def migrate_sqlite(path: Path, schema: str) -> dict:
    """Copy an sg.db into ``schema``, exactly (audit seq and hashes included), then check the chain."""
    d = db(schema)
    counts = {}
    with d.transaction():
        n = d.execute("SELECT (SELECT COUNT(*) FROM audit) + (SELECT COUNT(*) FROM groups)").fetchone()[0]
        if n:
            raise RuntimeError(f"schema {schema} already holds security groups or an audit trail: not copying "
                               f"{path} over it")  # fmt: skip
        for table in SQLITE_TABLES:
            cols, rows = _sqlite_rows(path, table)
            if not rows:
                counts[table] = 0
                continue
            d.executemany(f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))})", rows)  # noqa: S608
            counts[table] = len(rows)
        for table, col in (("audit", "seq"), ("requests", "id")):
            d.execute(f"SELECT setval(pg_get_serial_sequence('{table}', '{col}'), "
                      f"GREATEST((SELECT COALESCE(MAX({col}), 0) FROM {table}), 1), "
                      f"(SELECT COUNT(*) > 0 FROM {table}))")  # noqa: S608
    import sg_db

    st = sg_db.Store(schema=schema)
    try:
        ok, entries, why = st.verify()
    finally:
        st.close()
    if not ok:
        raise RuntimeError(f"the audit trail did not survive the copy: {why}")
    counts["audit_verified"] = entries
    return counts


def cmd_migrate(args) -> int:
    import gzip

    import sg_ipintel

    root = home_dir()
    sg_ipintel.set_data_dir(root)
    schema = schema_for_dir(root)
    moved: list[Path] = []
    sqlite_path = Path(os.environ.get("SG_TIGHTENER_DB") or root / "sg.db").expanduser()
    if sqlite_path.exists() and not str(sqlite_path).startswith("postgres"):
        print(f"security group database {sqlite_path} ...")
        print("  ", migrate_sqlite(sqlite_path, schema))
        moved += [p for p in (sqlite_path, Path(f"{sqlite_path}-wal"), Path(f"{sqlite_path}-shm")) if p.exists()]
    review = root / "review"
    reads = sorted(review.glob("*.json.gz")) if review.is_dir() else []
    if reads:
        print(f"{len(reads)} account read(s) from {review} ...")
        kept = dropped = 0
        for p in reads:
            try:
                with gzip.open(p, "rt") as f:
                    doc = json.load(f)
            except (OSError, ValueError, EOFError) as exc:
                print(f"   {p.name}: not readable ({exc}), left where it is", file=sys.stderr)
                continue
            before = len(doc.get("chunks") or [])
            doc.setdefault("reads", [])
            review_save(doc, schema)
            kept += len(doc["chunks"])
            dropped += before - len(doc["chunks"])
            moved.append(p)
        print(f"   {kept} slices kept, {dropped} older than {RETENTION_DAYS} days not copied")
    others = [p for p in (review.glob("*.json") if review.is_dir() else [])] + [
        root / n for n in ("owners.json", "sso.json", "keys.json", "console-token")]
    if (root / "ipintel").is_dir():
        others += sorted((root / "ipintel").iterdir())
    for p in others:
        if p.is_file():
            File(p).write_bytes(p.read_bytes())
            moved.append(p)
    print(f"{sum(1 for p in others if p.is_file())} cache and state file(s) copied")
    cache = root / "report-cache.json"
    if cache.exists():
        moved.append(cache)  # rebuilt from the reads: not copied
    if moved and not args.keep:
        dest = root / f"migrated-{time.strftime('%Y%m%d-%H%M%S')}"
        for p in moved:
            target = dest / p.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(p), str(target))
        os.chmod(dest, 0o700)
        print(f"the files are in {dest}: delete it once the console looks right")
    return 0


def cmd_status(_args) -> int:
    conninfo = dsn()
    schema = schema_for_dir(home_dir())
    d = db(schema)
    safe = re.sub(r":[^:@/]*@", ":***@", conninfo)
    print(f"database {safe}, schema {schema}")
    for table in ("review_accounts", "review_slices", "audit", "groups", "rules", "requests", "files", "report_rows"):
        n = d.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]  # noqa: S608
        print(f"  {table:16} {n}")
    size = d.execute("SELECT pg_size_pretty(pg_database_size(current_database()))").fetchone()[0]
    oldest = d.execute("SELECT MIN(s) FROM review_slices").fetchone()[0]
    print(f"  size {size}; oldest flow-log slice "
          f"{time.strftime('%Y-%m-%d', time.gmtime(oldest)) if oldest else 'none'}; kept {RETENTION_DAYS} days")  # fmt: skip
    return 0


def cmd_prune(_args) -> int:
    print(prune(schema_for_dir(home_dir())))
    return 0


# ------------------------------------------------------------------------------------------- backup and restore
BACKUP_KEEP = 14


def backup_dir() -> Path:
    return home_dir() / "backups"


def _local_server() -> bool:
    """The database is the container ``setup`` made (so pg_dump runs inside it, matching its version)."""
    try:
        saved = dsn_file().read_text().strip()
    except OSError:
        return False
    return env_file().exists() and dsn() == saved


def _pg_tool(tool: str, *args: str) -> tuple[list, dict]:
    """(command, environment) for pg_dump or pg_restore against the database: inside the local container, or
    this computer's own copy for a server named by SG_TIGHTENER_PG_DSN. The password goes in the environment,
    never on the command line."""
    if _local_server():
        docker = _bin("docker")
        if not docker:
            raise RuntimeError("Docker is not installed")
        return ([docker, "compose", "-f", str(compose_file()), "--env-file", str(env_file()), "exec", "-T", "postgres",
                 tool, "-U", "sgt", "-d", "sgtightener", *args], {})  # fmt: skip
    exe = _bin(tool)
    if not exe:
        raise RuntimeError(f"{tool} is not installed on this computer (brew install libpq), and the database is not "
                           "the local container")  # fmt: skip
    from psycopg.conninfo import conninfo_to_dict

    parts = conninfo_to_dict(dsn())
    env = {f"PG{k.upper()}": str(v) for k, v in parts.items() if k in ("host", "port", "user", "password", "dbname")}
    env = {("PGDATABASE" if k == "PGDBNAME" else k): v for k, v in env.items()}
    return [exe, *args], env


def backup(out_dir: Path | None = None, keep: int = BACKUP_KEEP, say=print) -> Path:
    """pg_dump of the whole database (every schema) in PostgreSQL's custom format, written 0600, read back with
    pg_restore --list before it counts, then all but the newest ``keep`` backups in that folder deleted."""
    out_dir = Path(out_dir) if out_dir else backup_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)
    if not reachable()[0]:
        raise RuntimeError(f"the database does not answer ({reachable()[1]}): `python3 sg_store.py start` first")
    final = out_dir / f"sgtightener-{time.strftime('%Y%m%d-%H%M%S')}.dump"
    part = final.with_suffix(".dump.part")
    cmd, env = _pg_tool("pg_dump", "-Fc", "-Z", "6")
    fd = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            r = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, env={**os.environ, **env}, timeout=3600)
        if r.returncode != 0:
            raise RuntimeError(f"pg_dump failed: {r.stderr.decode(errors='replace').strip()[-400:]}")
        n = _entries(part)
        if n == 0:
            raise RuntimeError("pg_dump wrote a file pg_restore cannot list")
        part.rename(final)
    finally:
        if part.exists():
            part.unlink()
    say(f"backed up to {final} ({final.stat().st_size / 1e6:.1f} MB, {n} entries, checked)")
    old = sorted(out_dir.glob("sgtightener-*.dump"))[:-keep] if keep > 0 else []
    for p in old:
        p.unlink()
    if old:
        say(f"deleted {len(old)} older backup(s); keeping the newest {keep}")
    return final


def _entries(path: Path) -> int:
    """How many objects a custom-format dump lists (0 if pg_restore cannot read it)."""
    cmd, env = _pg_tool("pg_restore", "--list")
    if _local_server():  # in the container: the file goes in on stdin
        cmd = [c for c in cmd if c not in ("-U", "sgt", "-d", "sgtightener")]
    with open(path, "rb") as f:
        r = subprocess.run(cmd + ([] if _local_server() else [str(path)]), stdin=f if _local_server() else None,
                           capture_output=True, env={**os.environ, **env}, timeout=600)  # fmt: skip
    if r.returncode != 0:
        return 0
    return sum(1 for line in r.stdout.decode(errors="replace").splitlines() if line and not line.startswith(";"))


def restore(path: Path, say=print) -> None:
    """Put a backup back: every object in it is dropped and recreated (pg_restore --clean), in one transaction,
    so a failure leaves the database as it was."""
    path = Path(path)
    if not path.is_file() or _entries(path) == 0:
        raise RuntimeError(f"{path} is not a backup pg_restore can read")
    if not reachable()[0]:
        raise RuntimeError(f"the database does not answer ({reachable()[1]}): `python3 sg_store.py start` first")
    args = ["--clean", "--if-exists", "--no-owner", "--single-transaction", "--exit-on-error"]
    cmd, env = _pg_tool("pg_restore", *args)
    if not _local_server():
        cmd = cmd + [str(path)]
    with open(path, "rb") as f:
        r = subprocess.run(cmd, stdin=f if _local_server() else None, capture_output=True,
                           env={**os.environ, **env}, timeout=3600)  # fmt: skip
    if r.returncode != 0:
        raise RuntimeError(f"pg_restore failed, nothing changed: {r.stderr.decode(errors='replace').strip()[-400:]}")
    say(f"restored {path}")


def cmd_backup(args) -> int:
    try:
        backup(args.dir, args.keep)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


def cmd_restore(args) -> int:
    if not args.yes:
        print(f"restore replaces everything the database holds now with {args.file}. "
              "Back up first (sg_store.py backup), then run again with --yes.", file=sys.stderr)  # fmt: skip
        return 2
    try:
        restore(args.file)
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        return 1
    import sg_db

    st = sg_db.Store()
    try:
        ok, n, why = st.verify()
    finally:
        st.close()
    print(f"audit trail intact: {n} entries" if ok else f"audit trail NOT intact after restore: {why}")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sg_store.py", description=__doc__.split("\n", 1)[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("setup", help="start a local PostgreSQL in Docker and create the tables")
    s.add_argument("--port", type=int, default=DEFAULT_PORT)
    m = sub.add_parser("migrate", help="copy ~/.sg-tightener's files into the database")
    m.add_argument("--keep", action="store_true", help="leave the files where they are")
    sub.add_parser("start", help="start the local database (and colima, when Docker's engine is not running)")
    sub.add_parser("status", help="where the database is and what it holds")
    sub.add_parser("prune", help="delete flow-log data older than 12 months")
    b = sub.add_parser("backup", help="pg_dump the whole database to ~/.sg-tightener/backups/")
    b.add_argument("--dir", type=Path, help="another folder (default ~/.sg-tightener/backups)")
    b.add_argument("--keep", type=int, default=BACKUP_KEEP, help="backups kept in that folder (0 keeps all)")
    r = sub.add_parser("restore", help="put a backup back, replacing what the database holds now")
    r.add_argument("file", type=Path)
    r.add_argument("--yes", action="store_true", help="yes, replace what the database holds now")
    args = p.parse_args(argv)
    try:
        return {"setup": cmd_setup, "start": cmd_start, "migrate": cmd_migrate, "status": cmd_status, "prune": cmd_prune,
                "backup": cmd_backup, "restore": cmd_restore}[args.cmd](args)
    except NotConfigured as exc:
        print(exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
