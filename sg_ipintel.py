#!/usr/bin/env python3
"""sg_ipintel.py — who an internet address belongs to: AWS (and which service), a SaaS provider, or a network by its AS number.

Everything is read from public lists downloaded to the data directory and looked up locally, so no address
from your estate ever leaves the machine:

* AWS's own ranges (ip-ranges.json), with the service and region of each;
* the ranges SaaS providers publish (Cloudflare, GitHub, Google, Atlassian, Okta, Datadog, Fastly, Oracle Cloud,
  plus the networks of Zscaler, Salesforce, Akamai and others by AS number);
* every routed IPv4 range with its AS number, owner and country (iptoasn.com, public domain).

AWS's list and the SaaS lists are read again after a day, the AS list after a week. Until a list has been read
once, a few well-known ranges stand in, so the report still labels the commonest sources. ``refresh`` downloads;
``get`` never waits for the network. The lists live under ``DATA_DIR/ipintel`` (``~/.sg-tightener`` unless
``set_data_dir`` says otherwise).

Used by ``sg_review.py``.
"""

from __future__ import annotations

import gzip
import io
import ipaddress
import json
import logging
import re
import threading
import time
import urllib.request
from array import array
from bisect import bisect_right
from pathlib import Path

log = logging.getLogger("sg_ipintel")

AGENT = "sg-tightener"
DATA_DIR = Path.home() / ".sg-tightener"
DAY = 86400
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
ASN_URL = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
# (name, url, how to read it). GitHub Actions runs on Azure's shared ranges, so it is left out: it would
# name every Azure address GitHub.
SAAS_FEEDS = [
    ("Cloudflare", "https://www.cloudflare.com/ips-v4", "lines"),
    ("GitHub", "https://api.github.com/meta", "github"),
    ("Google Cloud (a customer's server)", "https://www.gstatic.com/ipranges/cloud.json", "google"),
    ("Google", "https://www.gstatic.com/ipranges/goog.json", "google"),
    ("Atlassian", "https://ip-ranges.atlassian.com/", "atlassian"),
    ("Okta", "https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json", "walk"),
    ("Datadog", "https://ip-ranges.datadoghq.com/", "datadog"),
    ("Fastly", "https://api.fastly.com/public-ip-list", "walk"),
    ("Oracle Cloud (a customer's server)", "https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", "walk"),
]
GITHUB_KEYS = ("hooks", "web", "api", "git", "packages", "pages", "importer", "dependabot")
# ------------------------------------------------------------------------------------- who runs a network
# Each source outside your ranges and AWS's is put in one of these groups. "kind" is the page's kind of source:
# saas for a provider's own service (its traffic is the provider acting for you or for a partner), internet for
# networks where anyone can be behind the address (rented servers, scanners, anonymisers, ISPs).
GROUPS = {
    "cdn": ("CDN and edge", "saas"),
    "security": ("Secure access and security service", "saas"),
    "saas": ("SaaS and big-tech service", "saas"),
    "hosting": ("Hosting and cloud servers (anyone's)", "internet"),
    "scanner": ("Internet scanner", "internet"),
    "anon": ("Tor or VPN exit", "internet"),
    "other": ("Other network (ISP, business)", "internet"),
}
# What each group means for a rule that lets it in.
GROUP_NOTE = {
    "cdn": "A CDN's addresses carry every one of its customers' traffic: allowing them allows any site or worker on it.",
    "security": "A secure access service (Zscaler, Netskope and the like) sends every customer's users out from the "
                "same addresses: allowing them allows every customer of that service, not only your partner.",
    "saas": "A provider's own service, for example a webhook or an integration.",
    "hosting": "Anyone can rent a server here: the address says nothing about who is behind it.",
    "scanner": "Scans the whole internet for open ports. Never needs a rule.",
    "anon": "An anonymising exit: whoever is behind it cannot be known.",
    "other": "An ISP or business network.",
}
# AS numbers known well enough to name by number: (provider, group, service type).
ORG_ASNS = {
    **{a: ("Microsoft", "saas", "Microsoft 365, Azure services") for a in (8075, 12076, 8068, 8069)},
    **{a: ("Google", "saas", "Google services") for a in (15169, 19527, 36040)},
    396982: ("Google Cloud", "hosting", "Google Cloud customer servers"),
    **{a: ("Cloudflare", "cdn", "CDN, proxy and Workers") for a in (13335, 209242)},
    **{a: ("Akamai", "cdn", "CDN and edge") for a in (20940, 16625, 21342, 32787)},
    63949: ("Akamai Connected Cloud (Linode)", "hosting", "Cloud servers"),
    54113: ("Fastly", "cdn", "CDN and edge"),
    36459: ("GitHub", "saas", "Developer platform"),
    **{a: ("Zscaler", "security", "Secure web gateway (SASE)") for a in (22616, 62044, 53813)},
    14340: ("Salesforce", "saas", "CRM"),
    32934: ("Meta", "saas", "Social"),
    14413: ("LinkedIn", "saas", "Social"),
    19679: ("Dropbox", "saas", "File sharing"),
    2635: ("Automattic", "saas", "WordPress.com"),
    30103: ("Zoom", "saas", "Video meetings"),
    11377: ("SendGrid (Twilio)", "saas", "Email delivery"),
    14061: ("DigitalOcean", "hosting", "Cloud servers"),
    16276: ("OVHcloud", "hosting", "Cloud servers"),
    24940: ("Hetzner", "hosting", "Cloud servers"),
    20473: ("Vultr", "hosting", "Cloud servers"),
    31898: ("Oracle Cloud", "hosting", "Oracle Cloud customer servers"),
    **{a: ("Alibaba Cloud", "hosting", "Cloud servers") for a in (45102, 37963)},
    132203: ("Tencent Cloud", "hosting", "Cloud servers"),
    36351: ("IBM Cloud", "hosting", "Cloud servers"),
    12876: ("Scaleway", "hosting", "Cloud servers"),
    51167: ("Contabo", "hosting", "Cloud servers"),
    **{a: ("Censys", "scanner", "Internet-wide scanning") for a in (398324, 398705, 398722)},
    211298: ("Driftnet", "scanner", "Internet-wide scanning"),
    208843: ("Alpha Strike Labs", "scanner", "Internet-wide scanning"),
}  # fmt: skip
# Otherwise, by words in the network owner's registered name: (pattern, provider, group, service type).
ORG_NAMES = [(re.compile(rx, re.IGNORECASE), *rest) for rx, *rest in (
    (r"\bshodan\b", "Shodan", "scanner", "Internet-wide scanning"),
    (r"\bcensys\b", "Censys", "scanner", "Internet-wide scanning"),
    (r"\bonyphe\b", "ONYPHE", "scanner", "Internet-wide scanning"),
    (r"\bshadowserver\b", "Shadowserver", "scanner", "Internet-wide scanning"),
    (r"\brapid7\b", "Rapid7", "scanner", "Internet-wide scanning"),
    (r"\bbinaryedge\b", "BinaryEdge", "scanner", "Internet-wide scanning"),
    (r"\bleakix\b", "LeakIX", "scanner", "Internet-wide scanning"),
    (r"\bstretchoid\b", "Stretchoid", "scanner", "Internet-wide scanning"),
    (r"\brecyber\b", "Recyber", "scanner", "Internet-wide scanning"),
    (r"\bdriftnet\b", "Driftnet", "scanner", "Internet-wide scanning"),
    (r"\balpha ?strike\b", "Alpha Strike Labs", "scanner", "Internet-wide scanning"),
    (r"\btorservers\b|\btor exit\b|\btor-exit\b|\bfor-privacy\b|\bemerald onion\b", "Tor exit", "anon", "Anonymising relay"),
    (r"\bmullvad\b", "Mullvad VPN", "anon", "VPN exit"),
    (r"\bnordvpn\b|\bpackethub\b", "NordVPN", "anon", "VPN exit"),
    (r"\bproton ?(ag|vpn)\b", "Proton VPN", "anon", "VPN exit"),
    (r"\bm247\b", "M247", "hosting", "Servers and VPN exits"),
    (r"\bdatacamp\b|\bcdn77\b", "Datacamp (CDN77)", "hosting", "Servers and VPN exits"),
    (r"\bzscaler\b", "Zscaler", "security", "Secure web gateway (SASE)"),
    (r"\bnetskope\b", "Netskope", "security", "Secure web gateway (SASE)"),
    (r"\bpalo ?alto networks\b|\bpaloaltonetworks\b", "Palo Alto Networks", "security", "Prisma Access and Cortex Xpanse"),
    (r"\bcato ?networks\b", "Cato Networks", "security", "SASE"),
    (r"\bopendns\b|\bcisco umbrella\b", "Cisco Umbrella", "security", "Secure web gateway"),
    (r"\bforcepoint\b", "Forcepoint", "security", "Secure web gateway"),
    (r"\biboss\b", "iboss", "security", "Secure web gateway"),
    (r"\bmenlo ?security\b", "Menlo Security", "security", "Secure browsing"),
    (r"\bcrowdstrike\b", "CrowdStrike", "security", "Endpoint security"),
    (r"\bmimecast\b", "Mimecast", "security", "Email security"),
    (r"\bproofpoint\b", "Proofpoint", "security", "Email security"),
    (r"\bcloudflare\b", "Cloudflare", "cdn", "CDN, proxy and Workers"),
    (r"\bakamai\b", "Akamai", "cdn", "CDN and edge"),
    (r"\bfastly\b", "Fastly", "cdn", "CDN and edge"),
    (r"\bimperva\b|\bincapsula\b", "Imperva", "cdn", "CDN and WAF"),
    (r"\bedgecast\b|\bedgio\b", "Edgio", "cdn", "CDN and edge"),
    (r"\bstackpath\b", "StackPath", "cdn", "CDN and edge"),
    (r"\bgithub\b", "GitHub", "saas", "Developer platform"),
    (r"\bgitlab\b", "GitLab", "saas", "Developer platform"),
    (r"\batlassian\b", "Atlassian", "saas", "Jira, Confluence, Bitbucket"),
    (r"\bslack\b", "Slack", "saas", "Messaging"),
    (r"\bzoom[- ]video\b", "Zoom", "saas", "Video meetings"),
    (r"\bdropbox\b", "Dropbox", "saas", "File sharing"),
    (r"\bbox,? inc\b", "Box", "saas", "File sharing"),
    (r"\bdatadog\b", "Datadog", "saas", "Monitoring"),
    (r"\bnew ?relic\b", "New Relic", "saas", "Monitoring"),
    (r"\bpagerduty\b", "PagerDuty", "saas", "Incident response"),
    (r"\bsplunk\b", "Splunk", "saas", "Logging and SIEM"),
    (r"\bsumo ?logic\b", "Sumo Logic", "saas", "Logging"),
    (r"\bsendgrid\b", "SendGrid (Twilio)", "saas", "Email delivery"),
    (r"\bmailgun\b", "Mailgun", "saas", "Email delivery"),
    (r"\brocket science group\b|\bmailchimp\b", "Mailchimp", "saas", "Email delivery"),
    (r"\btwilio\b", "Twilio", "saas", "Messaging API"),
    (r"\bokta\b", "Okta", "saas", "Identity"),
    (r"\bsalesforce\b|\bexacttarget\b", "Salesforce", "saas", "CRM"),
    (r"\bservicenow\b", "ServiceNow", "saas", "IT service management"),
    (r"\bworkday\b", "Workday", "saas", "HR and finance"),
    (r"\badobe\b", "Adobe", "saas", "Creative and document services"),
    (r"\bdocusign\b", "DocuSign", "saas", "E-signature"),
    (r"\bstripe\b", "Stripe", "saas", "Payments"),
    (r"\bpaypal\b", "PayPal", "saas", "Payments"),
    (r"\bshopify\b", "Shopify", "saas", "E-commerce"),
    (r"\bautomattic\b", "Automattic", "saas", "WordPress.com"),
    (r"\bfacebook\b|\bmeta platforms\b", "Meta", "saas", "Social"),
    (r"\blinkedin\b", "LinkedIn", "saas", "Social"),
    (r"\btwitter\b", "X (Twitter)", "saas", "Social"),
    (r"\bapple\b", "Apple", "saas", "Apple services"),
    (r"\bmicrosoft\b", "Microsoft", "saas", "Microsoft 365, Azure services"),
    (r"\bgoogle-cloud\b|\bgoogle cloud\b", "Google Cloud", "hosting", "Google Cloud customer servers"),
    (r"\bgoogle\b", "Google", "saas", "Google services"),
    (r"\boracle\b", "Oracle Cloud", "hosting", "Oracle Cloud customer servers"),
    (r"\bdigitalocean\b", "DigitalOcean", "hosting", "Cloud servers"),
    (r"\bovh\b", "OVHcloud", "hosting", "Cloud servers"),
    (r"\bhetzner\b", "Hetzner", "hosting", "Cloud servers"),
    (r"\blinode\b", "Akamai Connected Cloud (Linode)", "hosting", "Cloud servers"),
    (r"\bvultr\b|\bchoopa\b", "Vultr", "hosting", "Cloud servers"),
    (r"\bscaleway\b|\bonline s\.?a\.?s\b", "Scaleway", "hosting", "Cloud servers"),
    (r"\bcontabo\b", "Contabo", "hosting", "Cloud servers"),
    (r"\bleaseweb\b", "Leaseweb", "hosting", "Servers"),
    (r"\bhostinger\b", "Hostinger", "hosting", "Web hosting"),
    (r"\bionos\b|\b1&1\b", "IONOS", "hosting", "Servers"),
    (r"\bgodaddy\b|\bunified ?layer\b", "GoDaddy (Newfold)", "hosting", "Web hosting"),
    (r"\balibaba\b|\baliyun\b", "Alibaba Cloud", "hosting", "Cloud servers"),
    (r"\btencent\b", "Tencent Cloud", "hosting", "Cloud servers"),
    (r"\bsoftlayer\b|\bibm cloud\b", "IBM Cloud", "hosting", "Cloud servers"),
    (r"\bcloud\.ru\b|\bcloudru\b", "Cloud.ru", "hosting", "Cloud servers"),
    (r"\bip volume\b", "IP Volume", "hosting", "Servers (often scanners)"),
    (r"\bcarinet\b", "CariNet", "hosting", "Servers (hosts Shodan's scanners)"),
)]  # fmt: skip
# The published lists each provider name comes from, and its group.
FEED_GROUP = {"Cloudflare": "cdn", "Fastly": "cdn", "Zscaler": "security", "Google Cloud (a customer's server)": "hosting",
              "Oracle Cloud (a customer's server)": "hosting"}  # fmt: skip
SAAS_ASNS = {a: v[0] for a, v in ORG_ASNS.items() if GROUPS[v[1]][1] == "saas"}  # kept for older callers


# Every pattern starts a word with a fixed three characters: an owner none of whose words start with one of
# them is skipped without trying the patterns (there are some 80,000 owners, and few match).
_WORD = re.compile(r"\w[\w&.]*")
_ORG_KEYS = {_WORD.match(alt.replace("\\b", "").replace("\\", "")).group()[:3].lower()
             for rx, *_r in ORG_NAMES for alt in rx.pattern.split("|")}  # fmt: skip


def org_of(asn: int | None, owner: str = "") -> tuple[str, str, str] | None:
    """(provider, group, service type) of a network, by AS number first, then by its owner's name."""
    if asn in ORG_ASNS:
        return ORG_ASNS[asn]
    if not owner:
        return None
    if not any(w[:3].lower() in _ORG_KEYS for w in _WORD.findall(owner)):
        return None
    for rx, *rest in ORG_NAMES:
        if rx.search(owner):
            return tuple(rest)
    return None


def feed_group(name: str) -> str:
    """The group of a name from a published list ("GitHub (hooks)" is GitHub's)."""
    return FEED_GROUP.get(name) or FEED_GROUP.get(name.split(" (")[0]) or "saas"


# Until the lists are first read: a few ranges whose owner is well known.
SEED_SAAS = [
    ("104.16.0.0/13", "Cloudflare"), ("172.64.0.0/13", "Cloudflare"), ("140.82.112.0/20", "GitHub (hooks)"),
    ("192.30.252.0/22", "GitHub (hooks)"), ("165.225.0.0/17", "Zscaler"), ("13.108.0.0/14", "Salesforce"),
    ("8.8.8.0/24", "Google"),
]  # fmt: skip
SEED_AWS = [
    ("54.228.16.0/26", "ROUTE53_HEALTHCHECKS", "eu-west-1"), ("54.232.40.64/26", "ROUTE53_HEALTHCHECKS", "sa-east-1"),
    ("13.244.0.0/15", "EC2", "af-south-1"), ("15.188.0.0/16", "EC2", "eu-west-3"), ("52.95.0.0/16", "AMAZON", ""),
    ("130.176.0.0/16", "CLOUDFRONT_ORIGIN_FACING", "GLOBAL"), ("3.0.0.0/9", "AMAZON", ""),
]  # fmt: skip
SEED_ASN = [
    ("162.142.125.0", "162.142.125.255", 398324, "US", "CENSYS-ARIN-01"),
    ("165.225.0.0", "165.225.127.255", 22616, "US", "ZSCALER-INC"),
    ("140.82.112.0", "140.82.127.255", 36459, "US", "GITHUB"),
    ("104.16.0.0", "104.23.255.255", 13335, "US", "CLOUDFLARENET"),
    ("13.108.0.0", "13.111.255.255", 14340, "US", "SALESFORCE"),
]  # fmt: skip
# AWS service names that are more telling than AMAZON, the catch-all every range also carries.
AWS_SERVICE = {
    "ROUTE53_HEALTHCHECKS": "Route 53 health checks", "CLOUDFRONT_ORIGIN_FACING": "CloudFront",
    "CLOUDFRONT": "CloudFront", "EC2": "EC2 (any AWS customer's server, or Lambda outside a VPC)",
    "API_GATEWAY": "API Gateway", "S3": "S3", "DYNAMODB": "DynamoDB", "GLOBALACCELERATOR": "Global Accelerator",
    "ROUTE53": "Route 53", "ROUTE53_RESOLVER": "Route 53 Resolver", "CODEBUILD": "CodeBuild",
    "EC2_INSTANCE_CONNECT": "EC2 Instance Connect", "WORKSPACES_GATEWAYS": "WorkSpaces", "CLOUD9": "Cloud9",
    "KINESIS_VIDEO_STREAMS": "Kinesis Video Streams", "CHIME_VOICECONNECTOR": "Chime", "AMAZON_CONNECT": "Connect",
    "AMAZON_APPFLOW": "AppFlow", "EBS": "EBS", "AMAZON": "AWS",
}  # fmt: skip

_lock = threading.Lock()
_memo: dict = {}


def set_data_dir(path) -> None:
    global DATA_DIR
    DATA_DIR = Path(path).expanduser()
    with _lock:
        _memo.clear()


def _dir():
    d = DATA_DIR / "ipintel"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get(url: str, timeout: float = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _nets(values) -> list[str]:
    out = []
    for v in values:
        try:
            n = ipaddress.ip_network(str(v).strip(), strict=False)
        except ValueError:
            continue
        if n.version == 4 and n.prefixlen:
            out.append(str(n))
    return out


def _walk(node, out: list) -> None:
    if isinstance(node, dict):
        for v in node.values():
            _walk(v, out)
    elif isinstance(node, list):
        for v in node:
            _walk(v, out)
    elif isinstance(node, str) and "/" in node:
        out += _nets([node])


def parse_feed(name: str, how: str, raw: bytes) -> list[tuple[str, str]]:
    """(cidr, label) pairs from one provider's published list."""
    if how == "lines":
        return [(c, name) for c in _nets(raw.decode("utf-8", "replace").split())]
    doc = json.loads(raw)
    if how == "github":
        return [(c, f"GitHub ({k})") for k in GITHUB_KEYS for c in _nets(doc.get(k) or [])]
    if how == "google":
        return [(c, name) for c in _nets(p.get("ipv4Prefix") for p in doc.get("prefixes") or [])]
    if how == "atlassian":
        return [(c, name) for c in _nets(i.get("cidr") for i in doc.get("items") or [])]
    if how == "datadog":
        return [(c, f"Datadog ({k})") for k, v in doc.items() if isinstance(v, dict)
                for c in _nets(v.get("prefixes_ipv4") or [])]  # fmt: skip
    found: list = []
    _walk(doc, found)
    return [(c, name) for c in found]


def parse_asn(raw: bytes) -> list[tuple]:
    """(start, end, asn, country, owner) rows of iptoasn's TSV, routed ranges only."""
    rows = []
    for line in gzip.GzipFile(fileobj=io.BytesIO(raw)).read().decode("utf-8", "replace").splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or parts[2] == "0":
            continue
        rows.append((parts[0], parts[1], int(parts[2]), parts[3], parts[4]))
    return rows


def _fresh(path, age: float) -> bool:
    try:
        return time.time() - path.stat().st_mtime < age
    except OSError:
        return False


def refresh(force: bool = False) -> dict:
    """Download whichever lists are older than their refresh age; keep the old copy when a download fails."""
    d = _dir()
    got = {}
    if force or not _fresh(d / "aws.json", DAY):
        try:
            doc = json.loads(_get(AWS_URL))
            rows = [(p["ip_prefix"], p.get("service", ""), p.get("region", "")) for p in doc.get("prefixes") or []]
            (d / "aws.json").write_text(json.dumps(rows))
            got["aws"] = len(rows)
        except (OSError, ValueError, KeyError) as exc:
            log.info("AWS ranges not read: %s", exc)
    if force or not _fresh(d / "saas.json", DAY):
        pairs: list = []
        for name, url, how in SAAS_FEEDS:
            try:
                pairs += parse_feed(name, how, _get(url, 15))
            except (OSError, ValueError, AttributeError) as exc:
                log.info("%s ranges not read: %s", name, exc)
        if pairs:
            (d / "saas.json").write_text(json.dumps(pairs))
            got["saas"] = len(pairs)
    if force or not _fresh(d / "asn.tsv.gz", 7 * DAY):
        try:
            raw = _get(ASN_URL, 90)
            parse_asn(raw)[:1]  # a broken download is not kept
            (d / "asn.tsv.gz").write_bytes(raw)
            got["asn"] = True
        except (OSError, ValueError, EOFError) as exc:
            log.info("AS number list not read: %s", exc)
    if got:
        with _lock:
            _memo.clear()
    return got


class PrefixIndex:
    """Longest-prefix match over many CIDRs: one dict per prefix length."""

    def __init__(self, rows) -> None:
        self.by_len: dict[int, dict[int, object]] = {}
        for cidr, payload in rows:
            try:
                n = ipaddress.IPv4Network(cidr, strict=False)
            except ValueError:
                continue
            self.by_len.setdefault(n.prefixlen, {}).setdefault(int(n.network_address), payload)
        self.lens = sorted(self.by_len, reverse=True)

    def get(self, ip: int):
        hit = self.match(ip)
        return hit[1] if hit else None

    def match(self, ip: int) -> tuple[str, object] | None:
        """(the longest published prefix holding ip, its payload), or None."""
        for plen in self.lens:
            net = ip >> (32 - plen) << (32 - plen) if plen else 0
            hit = self.by_len[plen].get(net)
            if hit is not None:
                return f"{ipaddress.IPv4Address(net)}/{plen}", hit
        return None

    def intervals(self) -> list[tuple[int, int]]:
        return merge([(k, k + (1 << (32 - p)) - 1) for p, d in self.by_len.items() for k in d])


class Intel:
    """Every lookup, built once from the downloaded lists (or the stand-ins)."""

    def __init__(self, aws_rows, saas_rows, asn_rows) -> None:
        # The most telling service wins: AMAZON is every range's catch-all, so it ranks last.
        best: dict[str, tuple] = {}
        for cidr, svc, region in aws_rows:
            cur = best.get(cidr)
            if cur is None or (cur[0] == "AMAZON" and svc != "AMAZON"):
                best[cidr] = (svc, region)
        self.aws = PrefixIndex(best.items())
        self.saas = PrefixIndex(saas_rows)
        self._saas_kind_rows = [(c, n) for c, n in saas_rows if GROUPS[feed_group(n)][1] == "saas"]
        self.asn_start = array("I")
        self.asn_end = array("I")
        self.asn_meta: list[tuple] = []
        for start, end, asn, cc, owner in sorted(asn_rows, key=lambda r: int(ipaddress.IPv4Address(r[0]))):
            try:
                s, e = int(ipaddress.IPv4Address(start)), int(ipaddress.IPv4Address(end))
            except ValueError:
                continue
            self.asn_start.append(s)
            self.asn_end.append(e)
            self.asn_meta.append((asn, cc, owner))
        self.counts = {"aws": len(best), "saas": len(saas_rows), "asn": len(self.asn_meta)}
        self._aws_iv: list | None = None
        self._saas_iv: list | None = None
        self._org: dict[tuple, tuple | None] = {}

    def org(self, asn, owner: str) -> tuple | None:
        k = (asn, owner)
        if k not in self._org:
            self._org[k] = org_of(asn, owner)
        return self._org[k]

    def saas_intervals(self) -> list[tuple[int, int]]:
        """Every address a provider's own service uses: its published ranges, and the blocks of networks named
        as a SaaS, CDN or secure access provider."""
        if self._saas_iv is None:
            iv = PrefixIndex(self._saas_kind_rows).intervals()
            for i, (asn, _cc, owner) in enumerate(self.asn_meta):
                o = self.org(asn, owner)
                if o and GROUPS[o[1]][1] == "saas":
                    iv.append((self.asn_start[i], self.asn_end[i]))
            self._saas_iv = merge(iv)
        return self._saas_iv

    def asn(self, ip: int) -> dict | None:
        i = bisect_right(self.asn_start, ip) - 1
        if i < 0 or ip > self.asn_end[i]:
            return None
        asn, cc, owner = self.asn_meta[i]
        block = f"{ipaddress.IPv4Address(self.asn_start[i])}-{ipaddress.IPv4Address(self.asn_end[i])}"
        return {"asn": asn, "country": cc, "owner": owner, "block": block}

    def aws_intervals(self) -> list[tuple[int, int]]:
        if self._aws_iv is None:
            self._aws_iv = self.aws.intervals()
        return self._aws_iv

    def label(self, ip: str) -> dict:
        """{kind: aws | saas | internet, name, service, region, asn, country, owner} for a public address."""
        try:
            n = int(ipaddress.IPv4Address(ip))
        except ValueError:
            return {"kind": "internet", "name": ip}
        a = self.asn(n) or {}
        out = {"asn": a.get("asn"), "country": a.get("country", ""), "owner": a.get("owner", ""),
               "block": a.get("block", "")}
        hit = self.aws.match(n)
        if hit:
            prefix, (svc, region) = hit
            name = AWS_SERVICE.get(svc, svc.replace("_", " ").title())
            return {**out, "kind": "aws", "service": svc, "region": region, "prefix": prefix,
                    "name": f"AWS {name}" + (f", {region}" if region and region != "GLOBAL" else "")}  # fmt: skip
        hit = self.saas.match(n)
        if hit:
            group = feed_group(hit[1])
            return {**out, "kind": GROUPS[group][1], "name": hit[1], "prefix": hit[0], "provider": hit[1].split(" (")[0],
                    "group": group, "group_name": GROUPS[group][0]}  # fmt: skip
        owner = a.get("owner") or ""
        org = self.org(a.get("asn"), owner) if a else None
        if org:
            provider, group, what = org
            return {**out, "kind": GROUPS[group][1], "name": provider, "provider": provider, "group": group,
                    "group_name": GROUPS[group][0], "what": what}  # fmt: skip
        return {**out, "kind": "internet", "group": "other", "group_name": GROUPS["other"][0],
                "name": f"AS{a['asn']} {owner}".strip() if a else "Unknown network"}  # fmt: skip


def get() -> Intel:
    """The lookups from whatever lists are on disk (the stand-ins for any not yet read)."""
    d = _dir()
    key = tuple(
        (p.name, p.stat().st_mtime) if p.exists() else (p.name, 0)
        for p in (d / "aws.json", d / "saas.json", d / "asn.tsv.gz")
    )
    with _lock:
        if _memo.get("key") == key:
            return _memo["intel"]
    aws_rows = _read_json(d / "aws.json") or SEED_AWS
    saas_rows = _read_json(d / "saas.json") or SEED_SAAS
    asn_rows = SEED_ASN
    try:
        asn_rows = parse_asn((d / "asn.tsv.gz").read_bytes()) or SEED_ASN
    except (OSError, ValueError, EOFError):
        pass
    intel = Intel(aws_rows, saas_rows, asn_rows)
    intel.counts["seed"] = [n for n, rows, seed in (("aws", aws_rows, SEED_AWS), ("saas", saas_rows, SEED_SAAS),
                                                    ("asn", asn_rows, SEED_ASN)) if rows is seed]  # fmt: skip
    with _lock:
        _memo.update(key=key, intel=intel)
    return intel


def _read_json(path):
    try:
        return [tuple(r) for r in json.loads(path.read_text())]
    except (OSError, ValueError):
        return None


# ------------------------------------------------------------------------------------- interval sets
# An address set as sorted, non-overlapping (first, last) integer pairs: how address space is counted.


def merge(iv) -> list[tuple[int, int]]:
    out: list[list[int]] = []
    for s, e in sorted(iv):
        if out and s <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return [(s, e) for s, e in out]


def intersect(a, b) -> list[tuple[int, int]]:
    out, i, j = [], 0, 0
    while i < len(a) and j < len(b):
        s, e = max(a[i][0], b[j][0]), min(a[i][1], b[j][1])
        if s <= e:
            out.append((s, e))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def subtract(a, b) -> list[tuple[int, int]]:
    out, j = [], 0
    for s, e in a:
        cur = s
        while j < len(b) and b[j][1] < cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] <= e:
            if b[k][0] > cur:
                out.append((cur, b[k][0] - 1))
            cur = max(cur, b[k][1] + 1)
            k += 1
        if cur <= e:
            out.append((cur, e))
    return out


def size(a) -> int:
    return sum(e - s + 1 for s, e in a)


def cidr_iv(cidr) -> tuple[int, int] | None:
    try:
        n = ipaddress.IPv4Network(str(cidr), strict=False)
    except ValueError:
        return None
    return int(n.network_address), int(n.broadcast_address)
