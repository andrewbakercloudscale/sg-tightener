"""sg_journal.py — the console's activity log: what it did, what you asked of it, and what went wrong.

The audit trail (sg_db) records every security group change and is never deleted. This is the other record,
for owning and supporting the console: each button pressed (with how long it took and whether it worked),
each read of many accounts as it is priced, confirmed, stopped and finished, scheduled reads, sign-in,
the network changing (Wi-Fi, a phone hotspot), the console starting, and every warning and error the
console logs, with its traceback.

It is a file, not a table, so it still works when the database is down (often the very thing to debug):
``journal.jsonl`` in the data folder, one JSON object a line, rotated at ``MAX_BYTES`` into ``journal.1.jsonl``
(so at most twice that is kept). Secrets are taken out before anything is written: tokens, AWS keys,
passwords in connection strings.

A support bundle (``bundle``) is a zip of what someone helping you needs: the journal, the end of the
console's log, versions, settings and health, every secret taken out.
"""

from __future__ import annotations

import io
import json
import logging
import os
import re
import threading
import time
import traceback
import zipfile
from pathlib import Path

MAX_BYTES = 2_000_000  # a journal file is rotated past this: at most twice this is kept
LEVELS = ("info", "warning", "error")
KINDS = {
    "action": "something asked of the console from its page",
    "read": "reading flow logs: pricing, confirming, stopping, finishing",
    "schedule": "the scheduled read",
    "signin": "signing in to AWS and out",
    "network": "the network changing (Wi-Fi, a phone hotspot)",
    "system": "the console starting, stopping, the database",
    "error": "a warning or error the console logged",
}

_SECRETS = [
    (re.compile(r"(?i)(postgres(?:ql)?://[^:/@\s]+:)[^@\s]+@"), r"\1***@"),  # password in a connection string
    (re.compile(r"\b(AKIA|ASIA)[A-Z0-9]{16}\b"), r"\1****************"),  # AWS access key ids
    (re.compile(r"(?i)(aws_secret_access_key|secret_access_key|secretaccesskey|aws_session_token|sessiontoken|session_token"
                r"|access_token|accesstoken|refresh_token|client_secret|clientsecret|password|passwd|token|x-sg-token)"
                r"([\"']?\s*[:=]\s*[\"']?)([^\s\"',}&]+)"), r"\1\2***"),  # fmt: skip
]
_SECRET_KEYS = re.compile(r"(?i)secret|token|password|passwd|dsn|key_id|access_key|session")


def redact(text: str) -> str:
    """The text with secrets replaced by ***."""
    for pat, rep in _SECRETS:
        text = pat.sub(rep, text)
    return text


def scrub(value, depth: int = 0):
    """A JSON-able copy with secret-looking keys blanked, long strings cut and secrets taken out of text."""
    if depth > 4:
        return "…"
    if isinstance(value, dict):
        return {str(k): ("***" if _SECRET_KEYS.search(str(k)) and v not in ("", None, False, True) else scrub(v, depth + 1))
                for k, v in list(value.items())[:40]}  # fmt: skip
    if isinstance(value, (list, tuple)):
        out = [scrub(v, depth + 1) for v in list(value)[:20]]
        return out + [f"… {len(value) - 20} more"] if len(value) > 20 else out
    if isinstance(value, str):
        v = redact(value)
        return v if len(v) <= 2000 else v[:2000] + "…"
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return redact(str(value))[:500]


class Journal:
    """Append-only JSON lines, rotated; safe to use from every thread. Never raises: a journal that cannot
    be written must not stop what it records."""

    def __init__(self, path: Path | str, max_bytes: int = MAX_BYTES):
        self.path = Path(path)
        self.old = self.path.with_name(self.path.stem + ".1" + self.path.suffix)
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self.failed = ""  # why the last write failed, shown on Support

    def record(self, kind: str, message: str, level: str = "info", account: str = "", **detail) -> dict:
        entry = {"at": round(time.time(), 3), "level": level if level in LEVELS else "info", "kind": kind,
                 "message": redact(str(message))[:1000]}  # fmt: skip
        if account:
            entry["account"] = str(account)
        if detail:
            entry["detail"] = scrub(detail)
        line = json.dumps(entry, default=str)
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists() and self.path.stat().st_size > self.max_bytes:
                    os.replace(self.path, self.old)
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
                with os.fdopen(fd, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self.failed = ""
            except OSError as exc:
                self.failed = str(exc)
        return entry

    def entries(self) -> list[dict]:
        """Every entry kept, oldest first."""
        out = []
        with self._lock:
            for p in (self.old, self.path):
                try:
                    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                for ln in lines:
                    try:
                        out.append(json.loads(ln))
                    except ValueError:
                        continue
        return out

    def recent(self, limit: int = 500, level: str = "", kind: str = "", text: str = "", since: float = 0,
               account: str = "") -> list[dict]:  # fmt: skip
        """Newest first. ``level`` "problems" is warnings and errors; ``kind`` one of KINDS."""
        rows = self.entries()
        text = text.lower().strip()
        out = []
        for e in reversed(rows):
            if since and e.get("at", 0) < since:
                break
            if level == "problems" and e.get("level") not in ("warning", "error"):
                continue
            if level in LEVELS and e.get("level") != level:
                continue
            if kind and e.get("kind") != kind:
                continue
            if account and e.get("account") != account:
                continue
            if text and text not in json.dumps(e).lower():
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def counts(self, since: float) -> dict:
        """{"warning": n, "error": n, "last_error": entry or None} since a time."""
        c = {"warning": 0, "error": 0, "last_error": None}
        for e in self.recent(limit=100000, since=since):
            lv = e.get("level")
            if lv in ("warning", "error"):
                c[lv] += 1
                if lv == "error" and c["last_error"] is None:
                    c["last_error"] = e
        return c

    def size(self) -> int:
        return sum(p.stat().st_size for p in (self.path, self.old) if p.exists())


class JournalHandler(logging.Handler):
    """Writes every warning and error logged anywhere in the console to the journal, with its traceback."""

    def __init__(self, journal: Journal):
        super().__init__(logging.WARNING)
        self.journal = journal
        self._busy = threading.local()

    def emit(self, record: logging.LogRecord) -> None:
        if getattr(self._busy, "on", False):  # the journal itself logging: never loop
            return
        self._busy.on = True
        try:
            detail = {"logger": record.name, "where": f"{record.module}.{record.funcName}:{record.lineno}"}
            if record.exc_info and record.exc_info[1] is not None:
                tb = "".join(traceback.format_exception(*record.exc_info))
                detail["traceback"] = tb[-6000:]
                detail["exception"] = f"{type(record.exc_info[1]).__name__}: {record.exc_info[1]}"
            self.journal.record("error", record.getMessage(), "error" if record.levelno >= logging.ERROR else "warning",
                                **detail)  # fmt: skip
        except Exception:  # noqa: BLE001 - a log handler must never raise
            pass
        finally:
            self._busy.on = False


def tail(path: Path | str, max_bytes: int = 400_000) -> str:
    """The end of a text file (its last ``max_bytes``), secrets taken out; "" when there is none."""
    try:
        p = Path(path)
        with p.open("rb") as f:
            f.seek(0, os.SEEK_END)
            n = f.tell()
            f.seek(max(0, n - max_bytes))
            data = f.read().decode("utf-8", errors="replace")
        if n > max_bytes:
            data = data.split("\n", 1)[-1]
        return redact(data)
    except OSError:
        return ""


def bundle(files: dict[str, object]) -> bytes:
    """A zip of ``{name: text | JSON-able}``: text as it is (redacted again), anything else as indented JSON."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, value in files.items():
            text = redact(value) if isinstance(value, str) else json.dumps(scrub(value) if not isinstance(value, list) else
                                                                           value, indent=2, default=str)  # fmt: skip
            z.writestr(name, text)
    return buf.getvalue()
