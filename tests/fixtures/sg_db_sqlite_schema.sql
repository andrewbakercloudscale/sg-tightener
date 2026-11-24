CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS regions (
  account TEXT NOT NULL, region TEXT NOT NULL, imported_at TEXT NOT NULL, synced_at TEXT NOT NULL,
  PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS groups (
  account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  name TEXT NOT NULL DEFAULT '', vpc_id TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, region, group_id));
CREATE TABLE IF NOT EXISTS rules (
  account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('desired', 'synced')),
  direction TEXT NOT NULL CHECK (direction IN ('in', 'out')),
  proto TEXT NOT NULL, from_port INTEGER NOT NULL, to_port INTEGER NOT NULL, source TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  PRIMARY KEY (account, region, group_id, state, direction, proto, from_port, to_port, source));
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, actor TEXT NOT NULL, origin TEXT NOT NULL,
  action TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL, group_id TEXT NOT NULL,
  detail TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '', ticket TEXT NOT NULL DEFAULT '',
  prev TEXT NOT NULL, hash TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS audit_group ON audit (account, region, group_id);
CREATE TABLE IF NOT EXISTS accounts (account TEXT PRIMARY KEY, name TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, account TEXT NOT NULL, region TEXT NOT NULL,
  proposer TEXT NOT NULL, reason TEXT NOT NULL, ticket TEXT NOT NULL DEFAULT '', changes TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'applied')),
  decided_by TEXT NOT NULL DEFAULT '', decided_at TEXT NOT NULL DEFAULT '', note TEXT NOT NULL DEFAULT '',
  applied_at TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS requests_status ON requests (status, account, region);
CREATE TABLE IF NOT EXISTS modes (
  account TEXT PRIMARY KEY, mode TEXT NOT NULL CHECK (mode IN ('surveillance', 'enforce')),
  set_by TEXT NOT NULL, set_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS permissions (
  account TEXT NOT NULL, region TEXT NOT NULL, checked_at TEXT NOT NULL, actor TEXT NOT NULL,
  ok INTEGER NOT NULL, result TEXT NOT NULL, PRIMARY KEY (account, region));
CREATE TABLE IF NOT EXISTS assets (
  account TEXT NOT NULL, region TEXT NOT NULL, eni TEXT NOT NULL, instance TEXT NOT NULL DEFAULT '',
  asg TEXT NOT NULL DEFAULT '', kind TEXT NOT NULL DEFAULT '', vpc_id TEXT NOT NULL DEFAULT '',
  ips TEXT NOT NULL DEFAULT '[]', groups TEXT NOT NULL DEFAULT '[]', description TEXT NOT NULL DEFAULT '',
  observed_at TEXT NOT NULL, PRIMARY KEY (account, region, eni));
CREATE TRIGGER IF NOT EXISTS audit_append_only_u BEFORE UPDATE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit trail is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_append_only_d BEFORE DELETE ON audit
  BEGIN SELECT RAISE(ABORT, 'the audit trail is append-only'); END;
