"""sg_store backup and restore: pg_dump inside the local container, checked before it counts, 0600, the
newest kept; restore only with --yes. The real dump and restore are checked against the running server by hand
(the tests' server is not the local container); here the commands and the file handling."""

from __future__ import annotations

import stat
import subprocess

import pytest

import sg_store


@pytest.fixture
def local(tmp_path, monkeypatch):
    monkeypatch.setattr(sg_store, "home_dir", lambda: tmp_path)
    monkeypatch.setattr(sg_store, "reachable", lambda: (True, ""))
    monkeypatch.setattr(sg_store, "_local_server", lambda: True)
    monkeypatch.setattr(sg_store, "_bin", lambda name: f"/bin/{name}")
    calls = []

    def run(cmd, stdout=None, stdin=None, stderr=None, capture_output=False, env=None, timeout=None):
        calls.append(cmd)
        if "pg_dump" in cmd:
            stdout.write(b"PGDMP fake")
            return subprocess.CompletedProcess(cmd, 0, None, b"")
        if "--list" in cmd:
            ok = stdin.read() == b"PGDMP fake"
            return subprocess.CompletedProcess(cmd, 0 if ok else 1, b";\n1; table rules\n2; table audit\n", b"")
        return subprocess.CompletedProcess(cmd, 0, b"", b"")

    monkeypatch.setattr(sg_store.subprocess, "run", run)
    return tmp_path, calls


def test_a_backup_is_dumped_in_the_container_checked_and_private(local):
    tmp, calls = local
    out = sg_store.backup(say=lambda _m: None)
    assert out.parent == tmp / "backups" and out.read_bytes() == b"PGDMP fake"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and stat.S_IMODE(out.parent.stat().st_mode) == 0o700
    dump = calls[0]
    assert dump[:2] == ["/bin/docker", "compose"] and "exec" in dump and "pg_dump" in dump and "-Fc" in dump
    assert any("--list" in c for c in calls), "read back before it counts"
    assert not list(out.parent.glob("*.part"))


def test_a_dump_that_fails_leaves_no_file_behind(local, monkeypatch):
    tmp, _ = local
    monkeypatch.setattr(sg_store.subprocess, "run",
                        lambda cmd, **k: subprocess.CompletedProcess(cmd, 1, None, b"pg_dump: error: boom"))
    with pytest.raises(RuntimeError, match="boom"):
        sg_store.backup(say=lambda _m: None)
    assert list((tmp / "backups").iterdir()) == []


def test_only_the_newest_backups_are_kept(local):
    tmp, _ = local
    d = tmp / "backups"
    d.mkdir()
    for i in range(5):
        (d / f"sgtightener-2026010{i}-000000.dump").write_bytes(b"old")
    (d / "notes.txt").write_text("mine")
    sg_store.backup(keep=3, say=lambda _m: None)
    left = sorted(p.name for p in d.iterdir())
    assert len([n for n in left if n.endswith(".dump")]) == 3 and "notes.txt" in left
    assert "sgtightener-20260104-000000.dump" in left and "sgtightener-20260102-000000.dump" not in left


def test_a_server_of_your_own_gets_the_password_in_the_environment_not_the_command_line(monkeypatch):
    monkeypatch.setattr(sg_store, "_local_server", lambda: False)
    monkeypatch.setattr(sg_store, "_bin", lambda name: f"/bin/{name}")
    monkeypatch.setenv(sg_store.DSN_ENV, "postgresql://u:s3cret@db.example:5433/sg")
    cmd, env = sg_store._pg_tool("pg_dump", "-Fc")
    assert cmd == ["/bin/pg_dump", "-Fc"] and "s3cret" not in " ".join(cmd)
    assert env == {"PGHOST": "db.example", "PGPORT": "5433", "PGUSER": "u", "PGPASSWORD": "s3cret", "PGDATABASE": "sg"}


def test_restore_needs_yes(tmp_path, capsys):
    f = tmp_path / "x.dump"
    f.write_bytes(b"PGDMP")
    assert sg_store.main(["restore", str(f)]) == 2
    assert "--yes" in capsys.readouterr().err


def test_restore_replaces_in_one_transaction(local):
    tmp, calls = local
    f = tmp / "x.dump"
    f.write_bytes(b"PGDMP fake")
    sg_store.restore(f, say=lambda _m: None)
    last = calls[-1]
    assert "pg_restore" in last and {"--clean", "--if-exists", "--single-transaction", "--exit-on-error"} <= set(last)
