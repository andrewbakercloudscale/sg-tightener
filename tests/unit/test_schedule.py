"""The console reads every chosen account's new flow logs by itself, once a day at 08:00 unless changed on the page:
caught up when a time was missed, waiting for a sign-in, and never spending over the limit without a yes."""

from __future__ import annotations

import time

import pytest

import sg_console
import sg_db


class FakeTargets:
    actor, account = "arn:aws:sts::111122223333:assumed-role/Admin/alice", "111122223333"


@pytest.fixture
def con(tmp_path):
    db = tmp_path / "sg.db"
    sg_db.Store(db).close()
    return sg_console.Console(str(db), targets=FakeTargets())


def at(hm: str, day: int = 0) -> float:
    lt = time.localtime()
    h, m = (int(x) for x in hm.split(":"))
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday + day, h, m, 0, 0, 0, -1))


def test_on_by_default_once_a_day_at_eight(con):
    s = con.schedule()
    assert s["on"] and s["times"] == ["08:00"] and s["max_cost"] > 0 and s["runs"] == []
    assert s["next"].endswith("08:00")


def test_a_time_is_due_once_it_passes_and_caught_up_for_a_few_hours_only():
    cfg = {"times": ["08:00", "20:00"]}
    assert sg_console._due_slot(cfg, at("07:59")) == ""
    assert sg_console._due_slot(cfg, at("08:00")).endswith("08:00")
    assert sg_console._due_slot(cfg, at("11:30")).endswith("08:00")  # asleep at eight: read when it wakes
    assert sg_console._due_slot(cfg, at("15:00")).endswith("08:00")  # asleep all morning: read once on waking
    assert sg_console._due_slot(cfg, at("19:00")) == ""  # the next read is under two hours away: wait for it
    assert sg_console._due_slot({**cfg, "on_wake": False}, at("15:00")) == ""  # catch-up off: only within 6 hours
    assert sg_console._due_slot({"times": ["08:00"]}, at("05:00")).endswith("08:00")  # closed overnight: yesterday's
    assert sg_console._due_slot(cfg, at("21:00")).endswith("20:00")
    assert sg_console._next_slot(cfg, at("21:00")).endswith("08:00")


def test_the_page_changes_it_and_bad_times_are_refused(con):
    s = con.set_schedule({"on": True, "times": ["20:00", "08:00"], "max_cost": 10})
    assert s["times"] == ["08:00", "20:00"] and s["max_cost"] == 10
    assert con.set_schedule({"on": False, "times": ["08:00"]})["on"] is False
    for bad in (["8am"], ["24:00"], []):
        with pytest.raises(sg_console.ConsoleError):
            con.set_schedule({"on": True, "times": bad})


def _due(con, monkeypatch, signed_in=True):
    monkeypatch.setattr(con, "_sso_ready", lambda: signed_in)
    started = []
    monkeypatch.setattr(con, "_scheduled_read", lambda slot, cfg: started.append(slot))
    monkeypatch.setattr(sg_console.threading, "Thread", lambda target, args, **kw: type("T", (), {"start": lambda self: target(*args)})())
    return started


def test_a_due_time_reads_once(con, monkeypatch):
    started = _due(con, monkeypatch)
    assert con.schedule_tick(at("08:05")).endswith("08:00")
    assert con.schedule_tick(at("08:06")) == "" and len(started) == 1


def test_signed_out_it_waits_and_reads_once_signed_in(con, monkeypatch):
    started = _due(con, monkeypatch, signed_in=False)
    assert con.schedule_tick(at("08:05")) == "" and con.schedule_tick(at("08:06")) == ""
    runs = con.schedule()["runs"]
    assert len(runs) == 1 and runs[0]["status"] == "waiting" and "sign in" in runs[0]["why"]
    monkeypatch.setattr(con, "_sso_ready", lambda: True)
    assert con.schedule_tick(at("09:00")).endswith("08:00") and len(started) == 1


def test_off_reads_nothing(con, monkeypatch):
    started = _due(con, monkeypatch)
    con.set_schedule({"on": False, "times": ["08:00"]})
    assert con.schedule_tick(at("08:05")) == "" and not started


class _Batch:
    def __init__(self, con, cost, unknown=0, status="confirm"):
        self.confirmed = False
        con.batch = {"status": status}
        con.read_all = lambda body: None
        con.batch_status = lambda: {"cost": cost, "cost_unknown": unknown, "to_read": 3, "accounts": 3}

        def confirm(body):
            self.confirmed = True
        con.read_all_confirm = confirm


def test_within_the_limit_it_starts_without_asking(con):
    b = _Batch(con, cost=4.5)
    con._scheduled_read("2026-11-25 08:00", {"days": 7, "max_cost": 25})
    assert b.confirmed and con.schedule()["runs"][-1]["status"] == "started"


def test_over_the_limit_it_is_priced_and_left_for_a_yes(con):
    b = _Batch(con, cost=80)
    con._scheduled_read("2026-11-25 08:00", {"days": 7, "max_cost": 25})
    last = con.schedule()["runs"][-1]
    assert not b.confirmed and last["status"] == "asking" and "US$25.00 limit" in last["why"]


def test_the_page_has_the_schedule_and_accounts_needing_attention():
    page = sg_console.ASSET.read_text()
    assert 'id="schedCard"' in page and "/api/schedule" in page
    assert 'id="fAttention"' in page and "Accounts that need attention" in page
