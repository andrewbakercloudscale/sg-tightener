"""The database not running: the console still serves its page, answers 503 with database false, and its
Start the database button starts colima (when Docker's engine is down) and then the container."""

from __future__ import annotations

import subprocess
import time

import sg_console
import sg_store

from tests.unit.test_console import _req, console  # noqa: F401 - the fixture


def test_a_stopped_database_is_a_503_the_page_can_offer_to_start(console, monkeypatch):  # noqa: F811
    def down(*_a, **_k):
        raise sg_store.NotConfigured("cannot reach the sg-tightener database: is it running?")

    monkeypatch.setattr(sg_console.Console, "state", down)
    status, out, _ = _req(console["port"], "GET", "/api/state")
    assert status == 503 and out["database"] is False
    status, page, _ = _req(console["port"], "GET", "/")
    assert status == 200 and 'id="dbStart"' in page and "/api/database/start" in page


def test_the_start_button_runs_the_start_in_the_background_and_reports_its_steps(console, monkeypatch):  # noqa: F811
    monkeypatch.setattr(sg_store, "server_status", lambda: {"ok": False, "why": "down", "local": True, "docker": True,
                                                             "colima": True, "engine": False, "can_start": True})
    ran = []
    monkeypatch.setattr(sg_store, "start_server", lambda say: (say("starting colima (Docker's engine) ..."), ran.append(1)))
    monkeypatch.setattr(sg_console.Console, "warm_reports", lambda self: None)
    status, _, _ = _req(console["port"], "POST", "/api/database/start", {}, header=False)
    assert status == 403  # a change: only the console's own page
    status, out, _ = _req(console["port"], "POST", "/api/database/start", {})
    assert status == 200
    for _ in range(50):
        status, out, _ = _req(console["port"], "GET", "/api/database")
        if not out["starting"]:
            break
        time.sleep(0.05)
    assert ran == [1] and out["steps"] == ["starting colima (Docker's engine) ..."] and out["error"] == ""


def test_start_server_starts_colima_first_when_dockers_engine_is_down(tmp_path, monkeypatch):
    monkeypatch.setattr(sg_store, "home_dir", lambda: tmp_path)
    (tmp_path / "pg.env").write_text("SGT_PG_PASSWORD=x\nSGT_PG_PORT=55432\n")
    up = {"db": False}
    monkeypatch.setattr(sg_store, "reachable", lambda: (up["db"], "" if up["db"] else "refused"))
    monkeypatch.setattr(sg_store, "_bin", lambda name: f"/bin/{name}")
    calls = []

    def run(cmd, timeout=120):
        calls.append(cmd[:2])
        if cmd[1] == "compose":
            up["db"] = True
        return subprocess.CompletedProcess(cmd, 1 if cmd[1] == "info" else 0, "", "")

    monkeypatch.setattr(sg_store, "_run", run)
    said = []
    sg_store.start_server(say=said.append)
    assert calls == [["/bin/docker", "info"], ["/bin/colima", "start"], ["/bin/docker", "compose"]]
    assert said[-1] == "the database is running"
    assert (tmp_path / "postgres" / "compose.yml").read_text() == sg_store.COMPOSE_YML


def test_start_server_says_why_when_it_cannot(tmp_path, monkeypatch):
    monkeypatch.setattr(sg_store, "home_dir", lambda: tmp_path)
    monkeypatch.setattr(sg_store, "reachable", lambda: (False, "refused"))
    try:
        sg_store.start_server(say=lambda _m: None)
        raise AssertionError("expected RuntimeError")
    except RuntimeError as exc:
        assert "sg_store.py setup" in str(exc)


def test_the_console_key_survives_a_stopped_database_and_is_kept_once_it_starts(monkeypatch):
    class Gone:
        def read_text(self):
            raise sg_store.NotConfigured("down")

        write_text = read_text

    monkeypatch.setattr(sg_console, "_UNSAVED_TOKEN", "")
    monkeypatch.setattr(sg_console, "token_file", lambda: Gone())
    tok = sg_console.lasting_token()
    assert len(tok) >= 24 and sg_console.lasting_token() == tok
    kept = []

    class Back:
        def write_text(self, t):
            kept.append(t.strip())

    monkeypatch.setattr(sg_console, "token_file", lambda: Back())
    sg_console._keep_unsaved_token()
    assert kept == [tok]
