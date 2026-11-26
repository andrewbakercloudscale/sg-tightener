"""Support: the activity log (what the console did and was asked, every error with its traceback), the health
checks, the support bundle with its secrets taken out, and `sg_console.py doctor`."""

from __future__ import annotations

import io
import json
import logging
import time
import zipfile

import pytest

import sg_console
import sg_journal
from tests.unit.test_console import ACCOUNT, REGION, _req, console  # noqa: F401 - the fixture


def test_secrets_are_taken_out_of_everything_written():
    fake_key = "AKIA" + "ABCDEFGHIJKLMNOP"  # made up, split so secret scanners do not stop the commit
    text = ("postgresql://sgt:hunter2@127.0.0.1:55432/sgt key " + fake_key + " "
            'aws_secret_access_key=abc/def+ghi "accessToken": "eyJraWQ" password=pw1 X-SG-Token: t0ken')
    out = sg_journal.redact(text)
    for secret in ("hunter2", "ABCDEFGHIJKLMNOP", "abc/def+ghi", "eyJraWQ", "pw1", "t0ken"):
        assert secret not in out, out
    assert "postgresql://sgt:***@127.0.0.1" in out and "AKIA" in out
    assert sg_journal.scrub({"dsn": "postgresql://a:b@h/d", "account": "1234", "keys": {"secret": "s", "n": 1}}) == \
        {"dsn": "***", "account": "1234", "keys": {"secret": "***", "n": 1}}


def test_the_journal_rotates_filters_newest_first_and_never_raises(tmp_path):
    j = sg_journal.Journal(tmp_path / "journal.jsonl", max_bytes=2000)
    for i in range(60):
        j.record("read", f"line {i}", "error" if i % 10 == 0 else "info", account="111122223333" if i % 2 else "")
    assert j.old.exists() and j.size() < 6000, "rotated: at most two files kept"
    rows = j.recent()
    assert rows[0]["message"] == "line 59" and all(a["at"] >= b["at"] for a, b in zip(rows, rows[1:]))
    assert {r["level"] for r in j.recent(level="problems")} == {"error"}
    assert all(r.get("account") == "111122223333" for r in j.recent(account="111122223333"))
    assert j.recent(text="line 5")[0]["message"] == "line 59"
    bad = sg_journal.Journal(tmp_path / "file" / "journal.jsonl")
    (tmp_path / "file").write_text("a file where the folder should be")
    bad.record("system", "cannot be written")  # no exception
    assert bad.failed


def test_a_logged_exception_lands_in_the_journal_with_its_traceback(tmp_path):
    j = sg_journal.Journal(tmp_path / "journal.jsonl")
    log = logging.getLogger("sg_test_journal")
    h = sg_journal.JournalHandler(j)
    log.addHandler(h)
    try:
        try:
            raise ValueError("password=letmein broke")
        except ValueError:
            log.exception("reading %s failed", "111122223333")
        log.info("not recorded: only warnings and errors")
    finally:
        log.removeHandler(h)
    (e,) = j.recent()
    assert e["level"] == "error" and e["kind"] == "error" and e["message"] == "reading 111122223333 failed"
    assert "ValueError" in e["detail"]["traceback"] and "letmein" not in json.dumps(e)


def test_each_action_on_the_page_is_recorded_with_its_outcome(console):  # noqa: F811
    p = console["port"]
    assert _req(p, "POST", "/api/propose", {"account": ACCOUNT, "region": REGION, "reason": "", "changes": []})[0] == 400
    assert _req(p, "POST", "/api/settings", {"wifi_only": True})[0] == 200
    status, act, _ = _req(p, "GET", "/api/activity?kind=action")
    assert status == 200 and set(act["kinds"]) >= {"action", "read", "error", "network"}
    new, old = act["rows"][0], act["rows"][1]
    assert new["message"] == "changed settings" and new["level"] == "info" and new["detail"]["asked"] == {"wifi_only": True}
    assert old["message"].startswith("proposed a change: ") and old["level"] == "warning" and old["account"] == ACCOUNT
    assert old["detail"]["status"] == 400 and old["detail"]["asked"]["changes"] == "0 item(s)"
    assert _req(p, "GET", "/api/activity?level=problems")[1]["rows"] == [old]


def test_health_lists_every_check_and_the_bundle_has_no_secrets(console, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sg_console, "_network", lambda fresh=False: {"metered": True, "interface": "en0", "why": "a phone hotspot"})
    p = console["port"]
    status, h, _ = _req(p, "GET", "/api/health")
    assert status == 200
    by = {c["key"]: c for c in h["checks"]}
    assert {"version", "database", "audit", "signin", "network", "batch", "schedule", "errors", "disk"} <= set(by)
    assert by["database"]["status"] == "ok" and by["audit"]["status"] == "ok"
    assert by["network"]["status"] == "warn" and "Wi-Fi" in by["network"]["fix"] and h["status"] in ("warn", "bad")
    _req(p, "POST", "/api/dsn-test", {"dsn": "postgresql://u:sup3rsecret@127.0.0.1:1/x"})
    conn = __import__("http.client").client.HTTPConnection("127.0.0.1", p, timeout=30)
    conn.request("GET", "/api/support/bundle", headers={"Host": f"127.0.0.1:{p}"})
    r = conn.getresponse()
    data = r.read()
    assert r.status == 200 and r.getheader("Content-Type") == "application/zip"
    assert "sg-tightener-support-" in r.getheader("Content-Disposition")
    z = zipfile.ZipFile(io.BytesIO(data))
    assert {"README.txt", "health.json", "settings.json", "activity.json", "console.log", "versions.json"} <= set(z.namelist())
    everything = b"".join(z.read(n) for n in z.namelist()).decode()
    assert "sup3rsecret" not in everything and "t0ken" not in everything
    assert "tested a database connection" in z.read("activity.json").decode()


def test_doctor_says_what_is_wrong_and_how_to_fix_it(monkeypatch):
    monkeypatch.setattr(sg_console, "_get_running", lambda port, path, timeout=30: (0, b"Connection refused"))
    out = io.StringIO()
    code = sg_console.doctor(1, out=out)
    text = out.getvalue()
    assert code == 1 and "FAIL  console" in text and "python sg_console.py install" in text
    assert "ok    database" in text and "ok    Python" in text


@pytest.mark.parametrize("secs,said", [(30, "30 s"), (600, "10 min"), (7200, "2 h"), (3 * 86400, "3 days")])
def test_spans_are_said_plainly(secs, said):
    assert sg_console._ago(secs) == said


def test_a_slow_answer_is_noted(console, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sg_console, "SLOW_GET", 0)
    p = console["port"]
    assert _req(p, "GET", "/api/state")[0] == 200
    for _ in range(50):  # noted just after the answer is sent
        rows = _req(p, "GET", "/api/activity?level=problems")[1]["rows"]
        if any(r["message"].startswith("slow answer: /api/state took") for r in rows):
            return
        time.sleep(0.05)
    raise AssertionError(rows)
