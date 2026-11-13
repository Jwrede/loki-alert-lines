# loki-alert-lines

A small proxy between the Loki ruler (or Grafana alerting) and Alertmanager.
For every firing alert it works out which log lines caused it, queries Loki
for them and adds them to the alert as an annotation. Alertmanager templates
can then show the lines in Slack, mail, PagerDuty or any other receiver:

```
{{ .Annotations.log_lines }}
```

Nothing changes in your alert rules. The proxy reads the rule expression from
the alert's generator URL (or from the Loki ruler API), turns the metric query
into a log query, narrows it to the labels of the alert instance and runs it
over the window that triggered the alert.

```
Loki ruler ──POST /api/v2/alerts──▶ loki-alert-lines ──POST /api/v2/alerts──▶ Alertmanager
Grafana alerting (Alertmanager      │        ▲
contact point) ─────────────────────┘        │ query_range (log query)
                                             └──────────── Loki / Grafana data source proxy
```

## Why

Loki alerting rules are metric queries. An alert says that
`count_over_time({app="api"} |= "ERROR" [5m])` was above zero, but not which
lines matched, so the person on call has to open Grafana and rebuild the query
by hand.

- [grafana/loki#5844](https://github.com/grafana/loki/issues/5844) "Add log
  message in alert": 113 reactions, 30 comments, open since April 2022. It
  proposes exactly this ("infer the log query from the metric query"). The
  Loki product manager wrote in April 2025 that they are aware of it; the last
  comment (March 2026) asks for updates.
- The workaround in that thread is to extract the message into a label with
  `| pattern` or `| json` and group by it, which only works for short,
  low-cardinality messages and one line per alert.
- Stack Overflow: [How to send alert for every error in my logs using
  Promtail / Loki - AlertManager?](https://stackoverflow.com/questions/62247602)
  (score 17, about 15,000 views) and [Including full log error message in alert
  notification using Loki + Grafana](https://stackoverflow.com/questions/76180602)
  (no answer).
- For Grafana-managed alerts with a Loki data source the situation is the
  same: a comment in #5844 from December 2024 notes there is no way to put the
  log line into a Slack message.

I found no existing tool for this. Robusta adds pod logs to alerts, but reads
them from Kubernetes rather than Loki and needs a cluster.

## How the log query is derived

For an alert produced by

```yaml
- alert: CheckoutErrors
  expr: sum by (app, msg) (count_over_time({env="prod"} | json | level="error" [5m])) > 10
  labels:
    severity: page
```

with alert labels `app="checkout", msg="payment declined", severity="page"`,
the proxy

1. takes the log range expression out of the metric query (stream selector
   and pipeline; `| unwrap ...` and the stages after it are dropped),
2. appends a label filter for every alert label except `alertname`, the
   rule's own static labels (read from the Loki ruler API or the Grafana
   rule), `grafana_folder` and labels passed with `-ignore-label`; if the
   query has exactly one `by (...)` clause, only those labels are used,
3. queries `[startsAt - range, now]` (capped by `-max-window`) for the newest
   `-lines` lines.

The `derive` subcommand shows the result without running anything:

```console
$ loki-alert-lines derive \
    -expr 'sum by (app, msg) (count_over_time({env="prod"} | json | level="error" [5m])) > 10' \
    -label alertname=CheckoutErrors -label app=checkout -label 'msg=payment declined' \
    -label severity=page -static severity=page
{env="prod"} | json | level="error" | app="checkout" | msg="payment declined"
range: 5m0s, offset: 0s, filters: app,msg, grouping: by (app, msg)
```

When the derived query is not what you want (for example a ratio of two log
queries, or a threshold on an unwrapped value), set it in the rule. Rule
annotations are templated by the ruler, so the alert labels are available:

```yaml
- alert: SlowRequests
  expr: max by (app) (max_over_time({job="lat"} | logfmt | unwrap latency_ms | __error__="" [1m])) > 500
  annotations:
    logs_query: '{job="lat", app="{{ $labels.app }}"} | logfmt | latency_ms > 500'
    log_lines_limit: "5"   # optional, "0" disables the lookup for this rule
```

## Example

From the end-to-end test against Loki 3.7.9 and Alertmanager v0.35.0. Five
lines were pushed for `job="e2e"`: three for `app="api"` (two `ERROR`, one
`INFO`) and one `ERROR` for `app="worker"`. The rule
`sum by (app) (count_over_time({job="e2e"} |= "ERROR" [1m])) > 0` fired twice,
and the alert for `app="api"` arrived in Alertmanager with:

```
log_lines_query: {job="e2e"} |= "ERROR" | app="api"
log_lines:
2026-11-13T05:17:58.9541812Z ERROR api one
2026-11-13T05:18:00.9541812Z ERROR api two
```

The rule `sum by (msg) (count_over_time({job="json"} | json | level="error" [1m])) > 2`
produced:

```
log_lines_query: {job="json"} | json | level="error" | msg="disk full"
log_lines:
2026-11-13T05:17:58.9541812Z {"level":"error","msg":"disk full","n":1}
2026-11-13T05:17:59.9541812Z {"level":"error","msg":"disk full","n":2}
2026-11-13T05:18:00.9541812Z {"level":"error","msg":"disk full","n":3}
```

## Install

```sh
go install github.com/Jwrede/loki-alert-lines@latest
# or
docker build -t loki-alert-lines . && docker run --rm -p 9097:9097 loki-alert-lines \
  -loki.url=http://loki:3100 -alertmanager.url=http://alertmanager:9093
```

Release binaries are on the releases page when a tag exists.

## Set up

Run the proxy and point the ruler at it instead of at Alertmanager:

```sh
loki-alert-lines -listen=:9097 \
  -loki.url=http://loki:3100 \
  -alertmanager.url=http://alertmanager:9093
```

```yaml
# Loki
ruler:
  alertmanager_url: http://loki-alert-lines:9097
  enable_api: true                # the proxy reads static rule labels from it
  # Loki 2.x only:
  enable_alertmanager_v2: true
```

The proxy accepts `/api/v1/alerts` and `/api/v2/alerts` under any path prefix
and always forwards to `/api/v2/alerts`. Several `-alertmanager.url` values
are sent to in parallel; the call succeeds if one of them accepts it. The
`X-Scope-OrgID` header of the ruler is used for the Loki calls and passed on
to Alertmanager, so multi-tenant setups keep their tenants.

A Slack receiver could then use:

```yaml
receivers:
  - name: slack
    slack_configs:
      - api_url: https://hooks.slack.com/services/...
        title: '{{ .CommonLabels.alertname }}'
        text: |-
          {{ range .Alerts }}{{ .Annotations.summary }}
          ```
          {{ .Annotations.log_lines }}
          ```
          {{ end }}
```

### Grafana-managed alerts

Grafana alert rules with a Loki data source work too. Create a contact point
of type **Alertmanager** with the URL of the proxy, and start the proxy with
Grafana credentials:

```sh
GRAFANA_TOKEN=glsa_... loki-alert-lines -listen=:9097 \
  -grafana.url=https://grafana.example.com \
  -alertmanager.url=http://alertmanager:9093
```

For these alerts the proxy takes the rule UID from the generator URL
(`/alerting/grafana/<uid>/view`), reads the rule with
`GET /api/v1/provisioning/alert-rules/<uid>`, picks the first query whose data
source is of type `loki`, and runs the log query through Grafana's data source
proxy, so it needs no direct Loki access. A query range of `[$__auto]` falls
back to the rule's relative time range.

### Annotations

| annotation | written by | meaning |
|---|---|---|
| `log_lines` | proxy | the lines, oldest first, one per line with an RFC 3339 timestamp |
| `log_lines_query` | proxy | the log query that was run |
| `log_lines_error` | proxy | why no lines could be added (the alert is forwarded anyway) |
| `log_lines_url` | proxy | Grafana Explore link, with `-grafana.url` |
| `logs_query` | rule | explicit log query (name set by `-query-annotation`) |
| `log_lines_limit` | rule | lines for this rule; `0` disables; removed before forwarding |

Resolved alerts and alerts that already carry `log_lines` are passed through
unchanged. A failed Loki query never blocks an alert.

### Flags

```
-listen :9097                 address to listen on
-alertmanager.url URL         Alertmanager to forward to (repeatable)
-alertmanager.username/-password-file/-bearer-token-file
-forward-auth=true            pass the ruler's Authorization header on
-forward-tenant=true          pass X-Scope-OrgID on
-loki.url URL                 Loki for queries and the ruler API
-loki.username/-password-file/-bearer-token-file, -loki.tenant
-grafana.url URL              Grafana; with credentials enables Grafana-managed alerts
-grafana.username/-password-file, -grafana.token-file ($GRAFANA_TOKEN)
-grafana.datasource-uid UID   Loki data source for Explore links of ruler alerts
-lines 10                     lines per alert
-max-line-length 500          cut longer lines
-max-bytes 4000               size limit of log_lines
-default-range 5m             window when the query has no range
-max-window 1h                never query a longer window
-query-timeout 5s, -forward-timeout 10s
-rules-refresh 30s            cache for the ruler rule list and Grafana rules
-cache-ttl 30s                cache identical queries (HA rulers send the same alert twice)
-ignore-label NAME            never filter on this label (repeatable)
-query-annotation logs_query
-log.json, -log.level info
```

`/metrics` exposes counters for received, enriched and skipped alerts, Loki
queries, Alertmanager calls and where each query came from
(`loki_alert_lines_query_source_total{source="generator_url|ruler_api|grafana_api|annotation"}`).

## Limits

- The LogQL handling is not a full parser. It finds stream selectors, their
  pipelines and ranges while respecting strings, parentheses and functions
  such as `ip()`. With two log queries in one rule (`A / B`) it uses the first;
  set `logs_query` for anything else.
- Labels that only exist after the log query (`label_replace`, vector
  matching) become filters that match nothing. Use `logs_query` or
  `-ignore-label`.
- Without the ruler API (`enable_api: false`) and without a single `by (...)`
  clause, the rule's static labels cannot be told apart from series labels;
  add them with `-ignore-label`.
- Loki 3 adds `service_name` and `detected_level` to series. When they end up
  in the alert labels they become filters as well; the query is longer but
  still correct.
- The ruler resends firing alerts every minute and the proxy refreshes the
  lines each time (subject to `-cache-ttl`). Alertmanager does not send a new
  notification only because an annotation changed; a notification shows the
  lines of the last update before it was sent.
- Grafana-managed alerts were tested with an admin user (basic auth). With a
  service account token, the account needs read access to alert rules through
  the provisioning API and to the data source.
- Not tested: Mimir or Cortex as Alertmanager, HA rulers against a real
  cluster (only the unit test for the cache), real Slack or mail receivers.

## Tests

```sh
go test -race ./...                       # unit tests, fake Loki/Grafana/Alertmanager
LAL_E2E=1 go test -v ./e2e/               # needs Docker; uses the host network
LAL_E2E=1 GRAFANA_IMAGE=grafana/grafana:13.3.1 go test -v ./e2e/
```

The end-to-end test starts Loki (with `auth_enabled: true` and the ruler),
Alertmanager with a webhook receiver and, optionally, Grafana with a
provisioned Loki data source, alert rule and Alertmanager contact point. It
pushes log lines, waits for the alerts and checks the annotations in
Alertmanager, the webhook notification and the proxy metrics. CI runs it
against Loki 3.7.9, 3.4.6, 2.9.17 and `latest`, Alertmanager v0.35.0 to v0.27.0,
and Grafana 13.3.1, 12.4.15 and `latest`, every Monday as well.

## License

MIT
