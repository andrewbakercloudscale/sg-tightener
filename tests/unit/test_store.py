"""sg_store: everything in PostgreSQL. Reads are frozen once fetched, kept 12 months, and an old sg.db copies
across exactly (the audit chain still verifies)."""

from __future__ import annotations

import gzip
import json
import sqlite3
import time
from pathlib import Path

import psycopg
import pytest

import sg_db
import sg_review
import sg_store

ACCT = "210987654321"
DAY = 86400


def _doc(now, ages_days):
    doc = sg_review.new_doc(ACCT, "acct")
    doc["regions"]["eu-west-1"] = {"snapshot": {"vpcs": []}, "taken": now}
    for age in ages_days:
        e = int(now - age * DAY)
        doc["chunks"].append({"r": "eu-west-1", "s": e - 3600, "e": e, "st": "ok", "b": 10, "rows": [["10.0.0.1"]],
                              "pub": [], "pc": False, "err": ""})
    doc["reads"].append({"at": now, "days": 7, "bytes": 1, "slices": len(ages_days)})
    return doc


def test_sql_is_translated_to_psycopg_parameters():
    assert sg_store.translate("SELECT * FROM t WHERE a = ? AND b LIKE 'x%?'", False) == \
        "SELECT * FROM t WHERE a = %s AND b LIKE 'x%%?'"
    assert sg_store.translate("INSERT INTO t VALUES (:at, :prev) -- 'a::b'", True) == \
        "INSERT INTO t VALUES (%(at)s, %(prev)s) -- 'a::b'"


def test_a_read_round_trips_and_saved_slices_are_never_written_again():
    now = time.time()
    doc = _doc(now, [1, 2, 3])
    sg_review.save(doc)
    ids = [c["k"] for c in doc["chunks"]]
    got = sg_review.load(ACCT)
    assert [c["k"] for c in got["chunks"]] == ids and got["regions"] == doc["regions"]
    assert got["chunks"][0]["rows"] == [["10.0.0.1"]] and got["reads"][0]["days"] == 7
    got["chunks"].append({**{k: v for k, v in got["chunks"][0].items() if k != "k"}, "s": 1, "e": int(now) - 60})
    del got["chunks"][1]  # one new, one dropped (e.g. a tail the hourly read replaced)
    sg_review.save(got)
    again = sg_review.load(ACCT)
    assert [c["k"] for c in again["chunks"]][:2] == [ids[0], ids[2]], "kept slices keep their rows"
    assert len(again["chunks"]) == 3
    assert sg_review.stamp(ACCT) >= now and ACCT in sg_review.cached_accounts()


def test_flow_log_data_is_kept_twelve_months():
    now = time.time()
    doc = _doc(now, [10, 200, 364, 366, 500])
    sg_review.save(doc)
    assert sorted(round((now - c["e"]) / DAY) for c in doc["chunks"]) == [10, 200, 364]
    assert len(sg_review.load(ACCT)["chunks"]) == 3
    # a year on, prune (and every save) deletes what has aged out
    assert sg_store.prune(now=now + 200 * DAY) == {"slices": 2, "reads": 0}
    assert [round((now - c["e"]) / DAY) for c in sg_review.load(ACCT)["chunks"]] == [10]


def test_forget_deletes_the_read_and_its_state():
    sg_review.save(_doc(time.time(), [1]))
    sg_review.save_watch(ACCT, {"sent": {"a": 1}})
    assert sg_review.forget(ACCT)
    assert sg_review.load(ACCT) is None and sg_review.load_watch(ACCT) == {"sent": {}}


def test_files_are_rows_keyed_by_path(tmp_path):
    f = sg_store.File(tmp_path / "x" / "state.json")
    with pytest.raises(FileNotFoundError):
        f.read_text()
    f.write_text("{}")
    assert f.read_text() == "{}" and f.stamp() and not (tmp_path / "x").exists()
    assert sg_store.File(f).read_text() == "{}"
    assert f.unlink() and not f.exists()


def test_an_sqlite_sg_db_copies_across_and_its_audit_chain_still_verifies(tmp_path):
    old = tmp_path / "old" / "sg.db"
    old.parent.mkdir()
    con = sqlite3.connect(old)
    con.executescript(Path(__file__).parents[1].joinpath("fixtures", "sg_db_sqlite_schema.sql").read_text())
    prev = sg_db.GENESIS
    for i in range(3):
        e = {"at": f"2026-01-0{i + 1}T00:00:00+00:00", "actor": "alice", "origin": "tool", "action": "import",
             "account": ACCT, "region": "eu-west-1", "group_id": "sg-1", "detail": "{}", "reason": "", "ticket": "",
             "prev": prev}
        e["hash"] = prev = sg_db._hash(e)
        con.execute("INSERT INTO audit (at, actor, origin, action, account, region, group_id, detail, reason, ticket, "
                    "prev, hash) VALUES (:at, :actor, :origin, :action, :account, :region, :group_id, :detail, :reason, "
                    ":ticket, :prev, :hash)", e)
    con.execute("INSERT INTO requests (at, account, region, proposer, reason, changes, status) VALUES "
                "('t', ?, 'eu-west-1', 'alice', 'r', '[]', 'applied')", (ACCT,))
    con.commit()
    con.close()
    schema = sg_store.schema_for_dir(tmp_path / "new")
    got = sg_store.migrate_sqlite(old, schema)
    assert got["audit"] == 3 and got["audit_verified"] == 3 and got["requests"] == 1
    st = sg_db.Store(schema=schema)
    with st:  # the copy carries on the chain and the numbering
        st.audit("bob", "tool", "note", ACCT, "eu-west-1", "sg-1", {})
    assert st.verify() == (True, 4, "")
    assert st.db.execute("SELECT MAX(seq) FROM audit").fetchone()[0] == 4
    with st:
        rid = st.db.execute("INSERT INTO requests (at, account, region, proposer, reason, changes, status) VALUES "
                            "('t', ?, 'r', 'p', 'r', '[]', 'pending') RETURNING id", (ACCT,)).fetchone()[0]
    assert rid == 2
    with pytest.raises(RuntimeError, match="already holds"):
        sg_store.migrate_sqlite(old, schema)  # never over data that is already there
    st.close()


def test_the_audit_trail_cannot_be_truncated(tmp_path):
    st = sg_db.Store(tmp_path / "sg.db")
    with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
        st.db.execute("TRUNCATE audit")
    st.close()


def test_without_a_database_the_tools_say_how_to_set_one_up(monkeypatch, tmp_path):
    monkeypatch.delenv(sg_store.DSN_ENV)
    monkeypatch.setattr(sg_store, "dsn_file", lambda: tmp_path / "none")
    with pytest.raises(sg_store.NotConfigured, match="sg_store.py setup"):
        sg_store.dsn()


def test_a_legacy_read_file_loads_into_the_database():
    now = time.time()
    raw = json.loads(json.dumps(_doc(now, [1, 400])))
    blob = gzip.compress(json.dumps(raw).encode())
    sg_store.review_save(json.loads(gzip.decompress(blob)))
    got = sg_review.load(ACCT)
    assert len(got["chunks"]) == 1 and got["name"] == "acct"
