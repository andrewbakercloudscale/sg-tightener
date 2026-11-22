#!/usr/bin/env bash
# sg-alerts.sh — the alerting jobs, for cron, systemd or launchd. Reads ~/.sg-tightener/alerts.env.
#
#   sg-alerts.sh watch       rejected traffic that needs attention, every 5 minutes (runs until stopped)
#   sg-alerts.sh watch-once  one pass of the above (for cron every 5 minutes instead of a service)
#   sg-alerts.sh reconcile   security group changes made outside sg-tightener (run hourly)
#   sg-alerts.sh daily       read yesterday's flow logs and rewrite the review page (run once a day)
set -euo pipefail

env_file="${SG_ALERTS_ENV:-$HOME/.sg-tightener/alerts.env}"
if [ ! -r "$env_file" ]; then
  echo "no settings file at $env_file: copy deploy/alerts/sg-tightener.env.example there and fill it in" >&2
  exit 2
fi
set -a
# shellcheck source=/dev/null
. "$env_file"
set +a

: "${SG_HOME:?set SG_HOME in $env_file}"
: "${SG_REGIONS:?set SG_REGIONS in $env_file}"
py="$SG_HOME/.venv/bin/python"
[ -x "$py" ] || { echo "no venv at $SG_HOME/.venv: run $SG_HOME/install.sh" >&2; exit 2; }
cd "$SG_HOME"

email=()
if [ -n "${SG_EMAIL_TO:-}" ]; then
  email=(--email-to "$SG_EMAIL_TO")
fi

case "${1:-}" in
  watch)      exec "$py" sg_review.py watch --regions "$SG_REGIONS" ${email[@]+"${email[@]}"} --loop ;;
  watch-once) exec "$py" sg_review.py watch --regions "$SG_REGIONS" ${email[@]+"${email[@]}"} ;;
  reconcile)  exec "$py" sg_db.py reconcile --regions "$SG_REGIONS" ;;
  daily)
    "$py" sg_review.py read --regions "$SG_REGIONS" --days 1 --yes
    exec "$py" sg_review.py report --out "$HOME/.sg-tightener/sg-review.html" ;;
  *) sed -n '2,7p' "$0" >&2; exit 2 ;;
esac
