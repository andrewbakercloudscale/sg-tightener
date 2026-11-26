# VPC flow logs in S3, read through Athena

Moving flow logs from CloudWatch Logs to S3 cuts the cost of keeping them by more than half, and with
Parquet it cuts the cost of reading them (what sg-tightener does on every read) by around ten times. This page
covers the layout to use, why, how to set it up across an organisation, and how sg-tightener reads it.

> **Status:** the console reads S3 flow logs through Athena (Settings → **Flow logs in S3 (Athena)**).
> The queries are unit tested against a fake Athena only. Run **Test and save** in the console, then read
> one account and compare it with its CloudWatch Logs read, before relying on it.

---

## The recommendation

**One bucket for the whole organisation, in the Log Archive account. Every account's flow logs go there
in Parquet, with Hive-compatible, per-hour partitions. One Athena table with partition projection reads every
account.**

This is the AWS standard: the [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/log-archive.html)
and Control Tower both put the organisation's logs (CloudTrail, Config, VPC flow logs) in one locked-down
**Log Archive** account. Workload accounts can write logs there but cannot read, change or delete them, so an
attacker in a workload account cannot cover their tracks.

```
Log Archive account (e.g. 999988887777), eu-west-1
└── s3://org-vpc-flow-logs/
    └── AWSLogs/
        ├── aws-account-id=111122223333/aws-service=vpcflowlogs/aws-region=eu-west-1/year=2026/month=11/day=26/hour=10/…parquet
        ├── aws-account-id=111122223333/aws-service=vpcflowlogs/aws-region=af-south-1/…
        └── aws-account-id=444455556666/…
Athena (in Log Archive, or a Security Tooling account allowed to read the bucket)
└── vpc_flow_logs.flow_logs   (partition projection: account, region, year, month, day, hour)
```

### One bucket, or one per account?

| | One organisation bucket (recommended) | A bucket per account |
|---|---|---|
| Who can delete the evidence | Only the Log Archive account | Anyone with admin in that account, including whoever compromised it |
| Querying across accounts | One table, one query | A table per account, or a crawler over many buckets |
| Adding an account | Nothing to do: the table already covers its folder | A bucket, a policy, a key, a table |
| Retention and lifecycle | One policy | One per account, drifting apart |
| Cost attribution | By prefix (S3 Storage Lens, or the account in the path) | By bucket |
| Blast radius of a bad bucket policy | Every account's logs | One account's |

A bucket per account only makes sense where a regulator requires an account's logs to stay apart.

### One region, or one per region?

Flow logs can be delivered to a bucket in another region. That is simplest, but each record crosses
regions, which can cost you data transfer. Two common choices:

- **One bucket, in the home region** (simplest; fine when most traffic is in one or two regions).
- **One bucket per region, all in Log Archive** (`org-vpc-flow-logs-eu-west-1`, `…-af-south-1`): no
  cross-region delivery, and it respects data residency, which South Africa (POPIA), for example, may
  require. Each regional bucket gets its own Athena table, and the console reads one table today. For now,
  point the console at the region with the most traffic, or ask for multi-table support.

### Amazon Security Lake?

[Security Lake](https://aws.amazon.com/security-lake/) does all of this for you: it collects flow logs
from every account into Log Archive, converts them to OCSF Parquet and manages the tables. It costs more
per GB than plain S3 delivery and its schema is OCSF, not the flow-log fields. If you already run it, that
table could be read instead (a small change to the queries). If not, plain S3 delivery below is cheaper
and enough.

---

## Setting it up

### 1. The bucket (Log Archive account)

- Block all public access, SSE-KMS with a customer-managed key, versioning on, and (optionally) Object Lock
  in governance mode for tamper evidence.
- A bucket policy that lets the log delivery service write for your organisation only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSLogDeliveryWrite",
      "Effect": "Allow",
      "Principal": {"Service": "delivery.logs.amazonaws.com"},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::org-vpc-flow-logs/AWSLogs/*",
      "Condition": {
        "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control", "aws:SourceOrgID": "o-xxxxxxxxxx"}
      }
    },
    {
      "Sid": "AWSLogDeliveryAclCheck",
      "Effect": "Allow",
      "Principal": {"Service": "delivery.logs.amazonaws.com"},
      "Action": ["s3:GetBucketAcl", "s3:ListBucket"],
      "Resource": "arn:aws:s3:::org-vpc-flow-logs",
      "Condition": {"StringEquals": {"aws:SourceOrgID": "o-xxxxxxxxxx"}}
    }
  ]
}
```

  The KMS key policy must also allow `delivery.logs.amazonaws.com` to `kms:GenerateDataKey*` and `kms:Decrypt`
  (same organisation condition), and the role that runs Athena to `kms:Decrypt`.
- Lifecycle: keep the query window (13 months covers a year-on-year view) in S3 Standard or Standard-IA,
  which Athena reads. Move older data to Glacier only if you never query it, because Athena cannot read Glacier.

### 2. The flow logs (every account, every VPC)

Use the same custom format as for CloudWatch Logs ([flow-logs.md](flow-logs.md)): `pkt-srcaddr`,
`tcp-flags` and `flow-direction` make the analysis accurate behind NAT and transit gateways, and let it
count connection resets.

```bash
aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-0123456789abcdef0 \
  --traffic-type ALL --max-aggregation-interval 60 \
  --log-destination-type s3 --log-destination arn:aws:s3:::org-vpc-flow-logs \
  --destination-options FileFormat=parquet,HiveCompatiblePartitions=true,PerHourPartition=true \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${vpc-id} ${subnet-id} ${tcp-flags} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction}'
```

Across an organisation, roll this out with a CloudFormation **StackSet** (service-managed, auto-deploy to
new accounts) or your account vending pipeline. Add the AWS Config rule `vpc-flow-logs-enabled` to catch
VPCs created without one. A VPC can have more than one flow log, so **keep the CloudWatch Logs flow log**
while the S3 one builds up.

### 3. The Athena table (Log Archive account)

In the console: Settings → **Flow logs in S3 (Athena)**, fill in the bucket, the Log Archive account and
the region, **Save**, then **Show the table SQL** and run it once in Athena. It creates a table over every
account's folder with partition projection, so there is no Glue crawler and nothing to add when an account
joins. A query names the account, region and hours, and Athena opens only those folders.

Give Athena a workgroup with a results bucket and a per-query data-scanned limit (10 GB is generous for
one slice).

### 4. Who may query

The console runs Athena in the account you name (Log Archive) **with the role chosen on Overview**
(RA-Read, for example). That role needs, in Log Archive:

- `athena:StartQueryExecution`, `GetQueryExecution`, `GetQueryResults`, `StopQueryExecution` on the workgroup
- `glue:GetDatabase`, `GetTable`, `GetPartitions` on the database and table
- `s3:GetObject`, `s3:ListBucket` on the flow-log bucket; `s3:PutObject`, `GetObject`, `ListBucket`,
  `GetBucketLocation` on the results location
- `kms:Decrypt` on the bucket's key

Log Archive does not need to be one of the accounts chosen for reading: the console signs in to it with
the same role.

### 5. Test, then read

**Test and save** runs one small query on the newest hour of the Log Archive account. Then read one
account that has both flow logs and compare the Remediate page with its CloudWatch Logs read.

---

## How sg-tightener reads it

- Each read lists the account's flow logs (`ec2:DescribeFlowLogs`, as now). A flow log whose destination is
  the bucket set up (same prefix, Parquet with Hive folders, or plain text with default folders) is read
  through Athena. Any other S3 destination is listed as not readable, as before.
- **Never twice:** in a region with both, the read uses S3 from when the S3 flow log was created and
  CloudWatch Logs before that. After the CloudWatch Logs flow log is deleted, everything comes from S3.
- Each slice is one Athena query that returns the same columns as the Logs Insights query (source, target,
  interface, protocol, port with replies folded, action, flows, bytes, resets, direction), so reports,
  Tighten, Rejected traffic, outbound and resets are unchanged. Athena has no 10,000-row limit (the cap is
  50,000 a slice), so busy VPCs need fewer, larger slices.
- The cost shown before a read learns from what the queries scanned, as with Logs Insights. Athena bills
  $5 per TB scanned (a 10 MB minimum per query), the same rate as Insights per GB. Parquet scans only the
  columns used, so the same hour usually costs around a tenth.

## Rough costs (us-east-1 list prices; check your region)

| | CloudWatch Logs | S3, Parquet |
|---|---|---|
| Delivery | $0.50 per GB (vended logs, first 10 TB) | $0.25 per GB, plus $0.035 per GB to convert to Parquet |
| Keeping it | $0.03 per GB-month (compressed) | $0.023 per GB-month, less in Standard-IA |
| Reading it (sg-tightener) | Logs Insights $0.005 per GB scanned, all of each record | Athena $5 per TB scanned, only the columns used (around 10× less) |
| Retention | A setting per log group | S3 lifecycle, one policy for every account |

## Moving over, step by step

1. Create the bucket, key and policy in Log Archive (once).
2. Add the S3 flow log next to each CloudWatch Logs one (StackSet). Leave CloudWatch Logs alone.
3. Create the Athena table (the console's SQL), grant the reading role, **Test and save**.
4. Read a few accounts. The console reads new hours from S3 and older hours from CloudWatch Logs.
5. After the analysis window has built up in S3 (90 days by default; as long as you look back), delete the
   CloudWatch Logs flow logs and let their log groups expire.
