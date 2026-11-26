"""Data use: a read of many accounts keeps each account's price across a restart, and reads can wait for Wi-Fi
while the Mac is on a phone hotspot."""

from __future__ import annotations

import subprocess
import time
import types

import pytest

import sg_console
import sg_db
import sg_ipintel as ipintel
import sg_review


class FakeTargets:
    actor = "arn:aws:sts::111122223333:assumed-role/AWSReservedSSO_ReadOnly_x/alice"

    def session(self, account):
        return types.SimpleNamespace(region_name="eu-west-1", client=lambda *a, **k: object())


class Chosen:
    def __init__(self, accounts):
        self._c = [{"account": a, "name": f"n{a[:3]}", "role": "CTO-Read"} for a in accounts]

    def chosen(self):
        return self._c


@pytest.fixture
def setup(tmp_path, monkeypatch):
    old = ipintel.DATA_DIR
    ipintel.set_data_dir(tmp_path / "data")
    monkeypatch.setattr(sg_db, "ensure_current", lambda *a, **k: [])
    monkeypatch.setattr(sg_console, "_network", lambda fresh=False: {"metered": False, "interface": "en0", "why": "Wi-Fi"})
    calls = []

    def plan(sess, doc, regions, days, now, say=None):
        calls.append(doc["account"])
        for r in regions:
            doc["regions"][r] = {"query_sets": [["lg"]]}
        return [("eu-west-1", now - 3600, now, [["lg"]], [])] * 2

    monkeypatch.setattr(sg_review, "plan_read", plan)
    monkeypatch.setattr(sg_review, "estimate", lambda doc, a, r, now=None: {"rate": 1e6})
    yield tmp_path, calls
    ipintel.set_data_dir(old)


def _wait(c, status):
    for _ in range(500):
        if c.batch_status()["status"] != status:
            return c.batch_status()
        time.sleep(0.01)
    raise AssertionError(c.batch_status())


def _ask_at(c):
    st = c.store()
    try:
        import json

        return json.loads(st.meta_get(c.BATCH_KEY, ""))["at"]
    finally:
        st.close()


ACCTS = [f"{i}" * 12 for i in range(1, 5)]


def test_a_restart_keeps_the_prices_already_worked_out(setup, monkeypatch):
    tmp_path, calls = setup
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(ACCTS))
    c.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0})
    b = _wait(c, "pricing")
    assert b["status"] == "confirm" and b["to_read"] == 4 and len(calls) == 4
    at = _ask_at(c)
    # the console restarts: the read is picked up again without pricing any account again
    c2 = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(ACCTS))
    c2.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0, "_resume_at": at})
    b2 = _wait(c2, "pricing")
    assert len(calls) == 4, "not priced again"
    assert b2["status"] == "confirm" and b2["to_read"] == 4 and b2["cost"] == b["cost"]
    assert all("not priced again" in j["lines"][-1] for j in c2.job_list())
    ran = []
    monkeypatch.setattr(sg_review, "run_read", lambda sess, doc, tasks, days, now, cancelled, progress=None:
                        ran.append(len(tasks)) or {"done": len(tasks), "bytes": 1e9})
    c2.read_all_confirm({})
    assert _wait(c2, "running")["status"] == "done" and ran == [2, 2, 2, 2]
    # a confirmed read clears what was kept: a later read is priced afresh
    st = c2.store()
    try:
        assert st.meta_get(c2.PRICED_KEY + ACCTS[0], None) is None
    finally:
        st.close()


def test_with_keep_prices_off_or_a_new_read_every_account_is_priced_again(setup):
    tmp_path, calls = setup
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(ACCTS))
    c.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0})
    _wait(c, "pricing")
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(ACCTS))
    c.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0})  # after a restart, a new read (not a resume)
    _wait(c, "pricing")
    assert len(calls) == 8
    at = _ask_at(c)
    st = c.store()
    try:
        with st:
            st.meta_set("keep_prices", False)
    finally:
        st.close()
    c2 = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(ACCTS))
    c2.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0, "_resume_at": at})
    _wait(c2, "pricing")
    assert len(calls) == 12


def test_on_a_hotspot_with_wifi_only_reads_wait(setup, monkeypatch):
    tmp_path, calls = setup
    monkeypatch.setattr(sg_console, "_network", lambda fresh=False: {"metered": True, "interface": "en0", "why": "a phone hotspot"})
    c = sg_console.Console(str(tmp_path / "sg.db"), targets=FakeTargets(), sso=Chosen(ACCTS))
    assert c.metered_hold() == "", "off by default"
    st = c.store()
    try:
        with st:
            st.meta_set("wifi_only", True)
    finally:
        st.close()
    assert "Wi-Fi" in c.metered_hold()
    with pytest.raises(sg_console.ConsoleError) as e:
        c.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0})
    assert e.value.status == 409 and "hotspot" in str(e.value)
    with pytest.raises(sg_console.ConsoleError):
        c.read_start({"account": ACCTS[0], "regions": "eu-west-1", "days": 1})
    assert not calls
    assert c.state()["network"] == {"metered": True, "interface": "en0", "why": "a phone hotspot", "wifi_only": True}
    monkeypatch.setattr(sg_console, "_network", lambda fresh=False: {"metered": False, "interface": "en0", "why": "Wi-Fi"})
    c.read_all({"regions": "eu-west-1", "days": 1, "min_spend": 0})
    assert _wait(c, "pricing")["status"] == "confirm"


def _fake_run(route, summaries, addrs=None):
    def run(cmd, **k):
        if cmd[:2] == ["route", "-n"]:
            out = route
        elif cmd[:2] == ["ipconfig", "getsummary"]:
            out = summaries.get(cmd[2], "")
        elif cmd[:2] == ["ipconfig", "getiflist"]:
            out = " ".join(summaries)
        elif cmd[:2] == ["ipconfig", "getifaddr"]:
            out = (addrs or {}).get(cmd[2], "")
        else:
            out = ""
        return types.SimpleNamespace(stdout=out)

    return run


@pytest.mark.parametrize("route,summaries,addrs,metered", [
    ("gateway: 172.20.10.1\n interface: en0\n", {"en0": "IsExpensive : FALSE"}, None, True),  # iPhone hotspot
    ("gateway: 192.168.8.1\n interface: en0\n", {"en0": "IsExpensive : TRUE"}, None, True),  # Android hotspot
    ("gateway: 192.168.1.1\n interface: en0\n", {"en0": "IsExpensive : FALSE"}, None, False),  # Wi-Fi at home
    ("gateway: 100.64.0.1\n interface: utun4\n", {"en0": "IsExpensive : TRUE", "en1": ""}, {"en0": "192.168.8.5"}, True),  # VPN on a hotspot
    ("gateway: 100.64.0.1\n interface: utun4\n", {"en0": "IsExpensive : FALSE"}, {"en0": "10.1.1.5"}, False),  # VPN on Wi-Fi
])
def test_a_phone_hotspot_is_recognised(monkeypatch, route, summaries, addrs, metered):
    monkeypatch.setattr(sg_console.sys, "platform", "darwin")
    monkeypatch.setattr(subprocess, "run", _fake_run(route, summaries, addrs))
    assert sg_console._network(fresh=True)["metered"] is metered
