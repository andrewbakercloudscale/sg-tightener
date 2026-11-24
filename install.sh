#!/usr/bin/env bash
# install.sh — set up sg-tightener: a Python venv with every package it needs, checked, and the public address
# lists (AWS, SaaS providers, AS numbers, Tor exits and the threat lists) downloaded once.
#
#   ./install.sh          the tools
#   ./install.sh --dev    the tools and the test suite's packages (pytest, moto)
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

dev=0
for arg in "$@"; do
  case "$arg" in
    --dev) dev=1 ;;
    -h|--help) sed -n '2,6p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg (try --help)" >&2; exit 2 ;;
  esac
done

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 not found on PATH. Install Python 3.9 or later (macOS: brew install python; Debian/Ubuntu: sudo apt install python3 python3-venv)" >&2
  exit 1
fi

py_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
required="3.9"
if [ "$(printf '%s\n' "$required" "$py_version" | sort -V | head -n1)" != "$required" ]; then
  echo "Python $required or later is required (found $py_version)" >&2
  exit 1
fi

if [ ! -x .venv/bin/python ]; then
  if ! python3 -m venv .venv; then
    echo "Could not create a virtual environment. On Debian/Ubuntu: sudo apt install python3-venv, then run ./install.sh again" >&2
    exit 1
  fi
fi

py=.venv/bin/python
"$py" -m pip install --quiet --upgrade pip
"$py" -m pip install --quiet -r requirements.txt
if [ "$dev" = 1 ]; then
  "$py" -m pip install --quiet -r requirements-dev.txt
fi

# Every package the tools import, checked, so a broken install fails here and not halfway through a read.
if ! "$py" -c 'import boto3, botocore, pandas, openpyxl, yaml, psycopg' 2>/dev/null; then
  echo "A package did not install. Run: $py -m pip install -r requirements.txt and read the error" >&2
  exit 1
fi
"$py" -c 'import sg_tightener, sg_db, sg_review, sg_console' || { echo "The tools did not load: see the error above" >&2; exit 1; }

# The database: PostgreSQL in a Docker container on 127.0.0.1 (colima on a Mac), unless SG_TIGHTENER_PG_DSN names
# one you run. Everything the tools keep (groups, the audit trail, flow-log reads, caches) is in it.
if [ -z "${SG_TIGHTENER_PG_DSN:-}" ] && [ ! -s "$HOME/.sg-tightener/pg.dsn" ]; then
  echo "Setting up the database (PostgreSQL in Docker, on 127.0.0.1 only)..."
  "$py" sg_store.py setup || { echo "The database is not set up: install Docker or colima (brew install colima docker docker-compose), then run: $py sg_store.py setup" >&2; exit 1; }
  if [ -e "$HOME/.sg-tightener/sg.db" ]; then
    echo "Copying what the earlier version kept in files (sg.db, reads, caches) into it..."
    "$py" sg_store.py migrate || echo "Not copied: run $py sg_store.py migrate and read the error" >&2
  fi
else
  "$py" sg_store.py start || { echo "The database does not answer: see the error above" >&2; exit 1; }
fi

# The public address lists, downloaded once now (each tool refreshes them when they are a day old). Not fatal:
# offline, the tools fall back to a few built-in ranges until the next run with a network.
echo "Downloading the public address lists (AWS, SaaS providers, AS numbers, Tor exits, threat lists)..."
"$py" - <<'PY' || echo "Address lists not downloaded now (offline?): the tools will fetch them on their next run."
import sg_ipintel
got = sg_ipintel.refresh()
c = sg_ipintel.get().counts
print(f"  AWS ranges {c['aws']:,} · SaaS ranges {c['saas']:,} · AS ranges {c['asn']:,} · Tor exits {c['tor'] + c['tor6']:,}"
      f" · threat-list entries {c['threat']:,}")
PY

cat <<'EOF2'

sg-tightener installed.

Activate the venv in your shell:
  source .venv/bin/activate

Then:
  python sg_review.py demo                                  # see it with no AWS access
  python sg_db.py import --regions eu-west-1 --profile P    # take your groups into the database
  python sg_review.py read --regions eu-west-1 --days 1     # read flow logs (start with a day)
  python sg_review.py report                                # write the page
  python sg_review.py watch --regions eu-west-1 --slack URL --loop   # alerts on rejected traffic
  python sg_console.py serve                                # the console
  python sg_store.py status                                 # the database: where, how big, what it holds

The database runs in Docker (colima on a Mac). After a restart, start it from the console's
"Start the database" button or with: python sg_store.py start
To have colima start at login: brew services start colima

Tests:
  ./install.sh --dev && python -m pytest
EOF2
