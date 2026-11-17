# Flow-log requirements

sg-tightener is only as good as the flow logs it reads. `analyse` and
`sg_diagnose` check the configuration before reading (`sg_extend` does not, and
assumes the default format), but it is faster to get it right first.

---

## What is required

| Requirement | Why | If missing |
|---|---|---|
| Flow logs on every VPC, subnet or interface you will tighten | No record, no evidence | Those sources are treated as unused |
| Traffic type `ALL` (or `ACCEPT` for `analyse`, `REJECT` for `sg_diagnose` and `sg_extend`) | `analyse` learns from accepted traffic; the incident tools read refused traffic | The run aborts |
| `${action}` in the format | To tell accepted from refused | The run aborts |
| `${srcaddr}` or `${pkt-srcaddr}` in the format | The address being learned | The run aborts |
| One format per destination | Records are parsed by position | The run aborts if formats are mixed |
| Delivered to CloudWatch Logs, or to S3 as text (`.gz` is fine) | The two supported readers; Parquet is not read | |

## Strongly recommended: `pkt-srcaddr`

The default format records `srcaddr`, the address of the *previous hop*.
Traffic that reaches an interface through a **transit gateway attachment** or a
**NAT gateway** is recorded under that gateway's private address, not the real
client. In a hub-and-spoke network that fills `approved.json` with gateway
addresses and misses the clients you meant to allow.

`pkt-srcaddr` is the original packet source. When it is in the format,
sg-tightener uses it. When it is not, `analyse` warns.

Flow logs cannot be edited. Create a new one with this format, let it collect
a full analysis window, then remove the old one:

```
${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status} ${pkt-srcaddr} ${pkt-dstaddr} ${flow-direction}
```

With `flow-direction` present, the CloudWatch reader also keeps only `ingress`
records.

## How the check works

`ec2:DescribeFlowLogs` finds the flow logs whose destination is your
`--log-group` or `--s3-bucket`. Their `LogFormat` decides the column order.

* **Errors (abort):** traffic type excludes the action being read; no
  `action` field; no source field; different formats feeding one destination.
* **Warnings (continue):** no `pkt-srcaddr`; a flow log not `ACTIVE`; delivery
  errors reported by AWS.
* **Unverified:** without `ec2:DescribeFlowLogs`, or when the logs are
  delivered from another account, the default format is assumed and a warning
  says so. If your logs use a custom format in that situation, the parsed
  columns will be wrong; grant the permission.

## Cost

Logs Insights queries are billed per GB scanned. A 90-day query over a busy
log group can scan a lot of data; try `--days 7` first to see the size.
