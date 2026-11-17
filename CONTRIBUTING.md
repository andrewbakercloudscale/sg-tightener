# Contributing

Thanks for helping. sg-tightener changes production firewall rules, so the bar
is correctness first.

## Setup

```bash
./install.sh
source .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest
```

## Rules for changes

- **Tests run offline.** No test may need AWS credentials or network access.
  Unit tests live in `tests/unit/`. End-to-end tests in `tests/integration/`
  run against moto (EC2, S3, STS, Organizations); Logs Insights is answered by
  `FakeLogs` in `tests/fixtures/flowgen.py`, which also generates synthetic
  flow logs for any topology.
- **Every bug fix gets a test that fails without the fix.**
- **Safety properties are not negotiable:** `plan` never writes; `apply` checks
  the snapshot hash and writes a manifest; `sg_extend` never revokes; nothing
  touches `0.0.0.0/0`, IPv6, security-group references or prefix lists.
- **Schemas are versioned.** A change to `approved.json`, `plan.json` or a
  manifest that older files cannot satisfy needs a new `/v2` schema.
- **Docs move with code.** Flags and defaults are documented in
  [docs/cli-reference.md](docs/cli-reference.md); update it in the same PR.
- Python 3.9 compatible: keep `from __future__ import annotations` at the top
  of every module.

## Pull requests

Describe what changes on a real network, how you tested it, and whether any
file format changed. CI runs the suite on Python 3.9 to 3.12.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue.
