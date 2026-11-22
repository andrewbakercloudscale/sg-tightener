# The security group console (`sg_console.py`)

One local web page for every account in [the database](database.md): browse every security group and
rule, propose a change, approve or reject someone else's, apply approved changes, reconcile with AWS,
search the audit trail, and see every rejected flow across an OU.

```bash
python sg_console.py install     # always running: starts at login, restarts if it stops, opens the browser
python sg_console.py serve       # or just for now: opens http://127.0.0.1:8765/?token=… (Ctrl-C stops it)
python sg_console.py open        # open it again later (same address every time: bookmark it)
python sg_console.py uninstall   # stop running in the background
```

The command line (`sg_db.py`) stays for scripts and cron; both work on the same database and the
same rules.

## Start here: sign in with AWS SSO and read your accounts

No AWS CLI, profile or command line is needed after the console is running.

1. **Sign in.** On the Overview, **AWS sign-in** asks for your AWS access portal address
   (`https://….awsapps.com/start`, the page you open to pick an AWS account) and its region. Both are
   filled in when your `~/.aws/config` already has them. **Sign in with AWS SSO** opens the AWS
   sign-in page in a new tab with a code; check the code matches and approve. If you already ran
   `aws sso login` for the same portal, you are signed in straight away.
2. **Choose accounts.** Every account your sign-in can use is listed, each with your roles there
   (read-only roles such as `ReadOnlyAccess` or `SecurityAudit` first). Tick the accounts, pick a role
   for each, **Use these accounts**.
3. **Read.** Pick the regions (`all` reads every enabled region) and how far back (start with 1 day),
   then **Read**. The account's security groups and network interfaces go into the console at once
   (free). The console then works out how much VPC flow log there is to read and shows the cost
   (CloudWatch Logs Insights, about US$0.005 a GB scanned): **Read flow logs (about US$…)** spends it,
   **Not now** does not. A bar shows the progress; **Stop** stops it.
4. **Review and tighten** opens the account's Security Group Review: the over-provisioning timeline,
   rejected traffic, and the Tighten panel, whose plan is proposed here as a change request.

Nothing is changed in AWS by any of this. Every account starts in **surveillance** mode; a change
reaches AWS only as a request a different person approves, in an account switched to enforce mode.

The sign-in token (valid for the session length Identity Center sets, usually 8 to 12 hours) is kept in
`~/.sg-tightener/sso.json` (mode `0600`) so an always-running console survives a restart; role
credentials are held only in memory and renewed as they expire. **Sign out** ends the session at
AWS. A role that can only read is enough to read; applying needs the
[write permissions](permissions.md).

![Signed in with AWS SSO: an account read, with the flow-log cost shown before it is spent](images/sg-console-sso-read.png)

## Always running

The **Always running** switch on the Overview (or `sg_console.py install`) keeps the console running
in the background, starts it when you log in and restarts it if it stops: a launchd agent on macOS
(`~/Library/LaunchAgents/com.sg-tightener.console.plist`), a systemd user service on Linux
(`~/.config/systemd/user/sg-console.service`). Turning it on from a console started by hand hands
over to the background copy at the same address; the page reloads by itself. Its log is
`~/.sg-tightener/console.log`. macOS does not let background programs read Desktop, Documents,
Downloads or iCloud Drive, so when sg-tightener lives there, turning it on copies the tool and the
packages it runs on (about 30 MB) to `~/.sg-tightener/app` and runs that copy; after updating
sg-tightener, turn Always running off and on again (or run `install` again) to refresh it. Proxy and CA bundle settings (`HTTPS_PROXY`, `AWS_CA_BUNDLE`, …) in
the environment it was turned on from are carried over. On Windows, start `sg_console.py serve` from
Task Scheduler at log on.

The address keeps the same token across restarts (`~/.sg-tightener/console-token`, mode `0600`), so a
bookmark keeps working; `serve --new-token` makes a new one and old bookmarks stop working.

![Overview: every account and region in the database](images/sg-console-overview.png)

## The five tabs

| Tab | What it shows and does |
|---|---|
| **Overview** | Every account and region: its **mode** (surveillance or enforce), groups, rules, assets, changes waiting to be applied, **whether this identity can apply there** (with a **Check** button: a DryRun of every write, nothing changes), when AWS was last read. The approvals mode, who you are acting as, and whether the audit trail's hash chain is intact. For an account `sg_review.py` has read, **Review and tighten** opens its Security Group Review (`/review?account=ID`), whose **Tighten** panel proposes the fitted rules here as a change request ([how](security-group-review.md#tighten-pull-the-room-back-by-kind-type-and-name)) |
| **Security groups** | Pick an account and region. Every group and rule, marked *to add* (approved, not in AWS yet) or *to remove* (in AWS, not wanted). **Propose a change**, **Propose removing** a rule, **Reconcile with AWS**, **Apply approved changes** (press twice; off in surveillance mode), **Propose keeping what AWS holds**. Below, every **asset** (network interface): what it is attached to, its addresses and groups, whether it can have a group of its own (auto scaling, EKS, ECS and AWS-managed interfaces cannot), and its **History** of group changes |
| **Change requests** | Requests waiting for approval, approved, applied, rejected, withdrawn. Approve, or reject with a note, someone else's request; withdraw your own. Apply an approved one. An **asset request** (from `sg_db.py asset-propose`) shows the interface, the group it gets, the rules narrowed and why, and once approved **Create the group and move** the interface |
| **Audit trail** | Every entry, newest first, searchable (who, why, ticket, group, rule) and filtered by time and origin. Changes made outside the tool are red, with who made them from CloudTrail |
| **Rejected traffic** | Every source the security groups and network ACLs refused, in every account `sg_review.py` has read, worst verdict first. Each source is marked **internal** or **external**, **IPv6**, **scanning**, and **new** (first seen in the last 7 days, never before in at least 14 days of flow logs), with when it was first seen. Filter by account, severity, risky ports, new addresses only, internal / external / IPv6 / scanning, and text. **Propose allowing** opens the change form with the source, port and a reason filled in |

![Change requests: approve or reject someone else's](images/sg-console-requests.png)

![Rejected traffic across every account read](images/sg-console-rejected-traffic.png)

## Surveillance and enforce

An account in **surveillance** mode (the default) is reported on and requests are recorded, but
nothing is applied: the Security groups tab says so and Apply is off. When the organisation is ready,
press **Check** on the Overview (or `sg_db.py check`), then
`sg_db.py mode enforce --account ID --reason "…"`. Setting the mode is deliberately a command, not a
button: it is the decision to let the tool change AWS.

## Two-person approval

Approval is on by default. A change is a **request**: proposed with a reason (and a ticket), approved
by a **different person**, then applied. Proposal, approval, rejection and apply are each an entry in
the audit trail.

1. Alice proposes: in the console, or `sg_db.py add|remove|exec|adopt` or `sg_db.py propose --plan plan.json`.
2. Bob approves (`sg_db.py approve 12` or the console). The request's changes become *desired*.
   Alice cannot approve her own request; rejecting needs a note saying why.
3. Anyone applies (`sg_db.py apply --region R` or the console). The request is marked applied once AWS
   holds every change.

"A different person" means a different AWS principal: the role session name for an assumed role
(`AWSReservedSSO_Admin_…/alice` and `…/bob` differ), the user name for an IAM user.

While approval is on, `sg_tightener apply` and `sg_compact apply` refuse and say to propose the plan
instead (`sg_db.py propose --plan plan.json --reason "…"`). `sg_extend` (break-glass) and `revert`
still go through, flagged in the audit trail, so an outage is never waiting for a second person.

One person running a lab can turn it off: `sg_db.py approvals off --reason "single operator"`
(audited). Requests are then approved by the proposer at once.

## Who you are

Signed in with AWS SSO on the page, the console acts as that sign-in, with the role chosen for each
account. Otherwise it acts as the AWS identity it runs as (`--profile`, `AWS_PROFILE`), read again for
every change, exactly like `sg_db.py`. To approve, the second person runs their own console (or
`sg_db.py approve`) with **their** credentials against the **same database file**: run sg-tightener
on one shared host (a bastion or a container with a volume), each person signing in with their own
SSO profile.

To apply or reconcile in another account, the console assumes `--role-name` (default
`OrganizationAccountAccessRole`) there, as `sg_db.py --ou-id` does.

## Security model

- **Localhost only.** It listens on `127.0.0.1`. To reach it from a laptop, use an SSH tunnel
  (`ssh -L 8765:127.0.0.1:8765 bastion`), never a public bind.
- **Token.** The URL printed at start carries a random token. Opening it sets an `HttpOnly`,
  `SameSite=Strict` cookie (30 days) and redirects to a URL without the token. Without the cookie every
  request is refused. The token is kept in `~/.sg-tightener/console-token` (`0600`) so the address
  stays the same; `serve --new-token` replaces it.
- **No cross-site changes.** Every change (POST) also needs the token in an `X-SG-Token` header and a
  JSON body: another web page cannot send either.
- **No DNS rebinding.** Requests whose `Host` is not `127.0.0.1:PORT` or `localhost:PORT` are refused.
- **Content Security Policy.** Only the page's own script runs (`script-src 'nonce-…'`), it can only
  talk to the console (`connect-src 'self'`), and it cannot be framed. Every value shown is escaped.
  The review page served at `/review` gets the same nonce on its scripts and loads nothing from
  outside.
- **The database is the boundary.** The console adds no privileges: AWS still decides what the
  identity may do, and the database still refuses a self-approval. The database file is `0600` in a
  `0700` directory.

## Rejected traffic across an OU

The **Rejected traffic** tab reads what `sg_review.py` keeps for each account in
`~/.sg-tightener/review/`. Fill it for a whole OU and keep it fresh:

```bash
python sg_review.py org   --regions eu-west-1 --ou-id ou-ab12-cdef3456 --days 7 --yes
python sg_review.py watch --regions eu-west-1 --ou-id ou-ab12-cdef3456 --slack https://hooks.slack.com/… --loop
```

`watch --ou-id` reads every account each loop (every 5 minutes, up to five minutes ago) and alerts on
rejected traffic that needs attention; an account whose role cannot be assumed is logged and the rest
carry on. The same table is on the org page (`sg-review-org/index.html`, **All rejected traffic**).

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--port` | `8765` | Port on 127.0.0.1 |
| `--db` | `$SG_TIGHTENER_DB` or `~/.sg-tightener/sg.db` | The database |
| `--profile` | the usual credential chain | AWS profile, for example an SSO one |
| `--role-name`, `--external-id` | `OrganizationAccountAccessRole` | Role assumed in other accounts to apply and reconcile (not used when signed in with SSO on the page) |
| `--new-token` | off | Make a new sign-in address (old bookmarks stop working) |
| `--no-browser` | off | Do not open the browser at start |
| `--data-dir` | `~/.sg-tightener` | Where `sg_review` keeps what it read |
