# Alerting: run it as a service

These files run sg-tightener's alerts without anyone at a keyboard:

| Job | What it posts | How often |
|---|---|---|
| `watch` | Rejected traffic that needs attention: a rule change that cut a caller off, your own traffic or AWS health checks refused, a partner's new address. Always, a **known malicious address** (on a threat list) let in or called out to. With `--alerts all`, also scanners or Tor exits let in, rules opened wide, exposure and hygiene | Every 5 minutes, about 10 minutes after the flow |
| `reconcile` | Security group changes made outside sg-tightener (console clicks, Terraform, scripts), with who made them from CloudTrail | Hourly |
| `daily` | Nothing: reads yesterday's flow logs and rewrites the review page, so the graphs stay current | Once a day |

Alerts go to Slack (an incoming webhook) and, optionally, email.

## Set up

```bash
./install.sh                                        # the venv, packages and address lists
cp deploy/alerts/sg-tightener.env.example ~/.sg-tightener/alerts.env
chmod 600 ~/.sg-tightener/alerts.env                # it holds the webhook and SMTP password
$EDITOR ~/.sg-tightener/alerts.env                  # SG_HOME, SG_REGIONS, AWS_PROFILE, Slack, email
deploy/alerts/sg-alerts.sh watch-once               # try one pass by hand
```

Then pick one way to run it:

- **Linux (systemd)**: `sg-tightener-watch.service` keeps `watch` running;
  `sg-tightener-reconcile.service` and `.timer` run `reconcile` hourly. Change `User`, the paths and
  `ReadWritePaths`, then copy them to `/etc/systemd/system/` and
  `systemctl enable --now sg-tightener-watch sg-tightener-reconcile.timer`.
- **macOS (launchd)**: `com.sg-tightener.watch.plist`, with the path changed, in
  `~/Library/LaunchAgents/`, then `launchctl load` it.
- **cron**: the lines in `crontab.example` (`watch-once` every 5 minutes, `reconcile` hourly, `daily`
  at 06:30).

## Credentials

The jobs read flow logs and security groups with the read-only policy (`iam-policy-read.json`). A
service cannot answer an SSO prompt, so give it a role (an instance profile on EC2, or a profile that
assumes a role) rather than an SSO session that expires. To watch every account in an OU, change the
`watch` line in `sg-alerts.sh` to add `--ou-id ou-…` (see
[Alert mode](../../docs/security-group-review.md#alert-mode-watch-real-time-alerts-on-rejected-traffic)).

## Cost

Each `watch` pass reads only what was not read yet, and skips a read estimated above `--max-cost`
(US$0.50 by default). A 5-minute loop costs about twice a once-a-day read of the same day.
