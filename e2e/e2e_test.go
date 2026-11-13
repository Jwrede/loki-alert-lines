// Package e2e runs loki-alert-lines between a real Loki ruler and a real
// Alertmanager in Docker (host network). Enable with LAL_E2E=1.
//
//	LOKI_IMAGE=grafana/loki:3.7.9 AM_IMAGE=prom/alertmanager:v0.35.0 LAL_E2E=1 go test -v ./e2e/
package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const tenant = "e2e"

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func run(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const rules = `groups:
  - name: e2e
    interval: 5s
    rules:
      - alert: AppErrors
        expr: sum by (app) (count_over_time({job="e2e"} |= "ERROR" [1m])) > 0
        labels:
          severity: page
        annotations:
          summary: 'errors in {{ $labels.app }}'
      - alert: JsonErrors
        expr: sum by (msg) (count_over_time({job="json"} | json | level="error" [1m])) > 2
      - alert: SlowRequests
        expr: max by (app) (max_over_time({job="lat"} | logfmt | unwrap latency_ms | __error__="" [1m])) > 500
        annotations:
          logs_query: '{job="lat", app="{{ $labels.app }}"} | logfmt | latency_ms > 500'
      - alert: Panics
        expr: count_over_time({job="raw"} |= "panic" [1m]) > 0
        labels:
          team: core
`

func lokiConfig(major string, port, grpc, mlPort, proxyPort int) string {
	schema := "v13"
	extra := "limits_config:\n  reject_old_samples: false\n"
	v2 := ""
	if major == "2" {
		schema = "v12"
		v2 = "  enable_alertmanager_v2: true\n"
	}
	return fmt.Sprintf(`auth_enabled: true
server:
  http_listen_address: 127.0.0.1
  http_listen_port: %d
  grpc_listen_address: 127.0.0.1
  grpc_listen_port: %d
  log_level: warn
memberlist:
  bind_addr: [127.0.0.1]
  bind_port: %d
common:
  instance_addr: 127.0.0.1
  path_prefix: /loki
  storage:
    filesystem:
      chunks_directory: /loki/chunks
      rules_directory: /loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory
schema_config:
  configs:
    - from: 2024-01-01
      store: tsdb
      object_store: filesystem
      schema: %s
      index:
        prefix: index_
        period: 24h
ruler:
  alertmanager_url: http://127.0.0.1:%d/prefix
%s  enable_api: true
  evaluation_interval: 5s
  poll_interval: 5s
  external_url: http://loki.example
  rule_path: /loki/rules-temp
  storage:
    type: local
    local:
      directory: /etc/lal-e2e/rules
analytics:
  reporting_enabled: false
%s`, port, grpc, mlPort, schema, proxyPort, v2, extra)
}

func grafanaProvisioning(lokiPort, proxyPort int) (ds, alerting string) {
	ds = fmt.Sprintf(`apiVersion: 1
datasources:
  - name: Loki
    uid: loki-e2e
    type: loki
    access: proxy
    url: http://127.0.0.1:%d
    jsonData:
      httpHeaderName1: X-Scope-OrgID
    secureJsonData:
      httpHeaderValue1: %s
`, lokiPort, tenant)
	alerting = fmt.Sprintf(`apiVersion: 1
contactPoints:
  - orgId: 1
    name: lal
    receivers:
      - uid: lal-am
        type: prometheus-alertmanager
        settings:
          url: http://127.0.0.1:%d
policies:
  - orgId: 1
    receiver: lal
    group_by: [alertname, app]
    group_wait: 1s
    group_interval: 1s
    repeat_interval: 1h
groups:
  - orgId: 1
    name: e2e
    folder: e2e
    interval: 10s
    rules:
      - uid: lal-grafana-errors
        title: GrafanaErrors
        condition: C
        data:
          - refId: A
            relativeTimeRange:
              from: 600
              to: 0
            datasourceUid: loki-e2e
            model:
              refId: A
              expr: 'sum by (app) (count_over_time({job="e2e"} |= "ERROR" [10m]))'
              queryType: instant
          - refId: B
            datasourceUid: __expr__
            model:
              refId: B
              type: reduce
              expression: A
              reducer: last
          - refId: C
            datasourceUid: __expr__
            model:
              refId: C
              type: threshold
              expression: B
              conditions:
                - evaluator:
                    type: gt
                    params: [0]
        noDataState: OK
        execErrState: OK
        for: 0s
        labels:
          severity: ticket
`, proxyPort)
	return ds, alerting
}

type hook struct {
	mu     sync.Mutex
	alerts []map[string]any
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var msg struct {
		Alerts []map[string]any `json:"alerts"`
	}
	json.NewDecoder(r.Body).Decode(&msg)
	h.mu.Lock()
	h.alerts = append(h.alerts, msg.Alerts...)
	h.mu.Unlock()
}

type amAlert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	GeneratorURL string            `json:"generatorURL"`
}

func TestE2E(t *testing.T) {
	if os.Getenv("LAL_E2E") != "1" {
		t.Skip("set LAL_E2E=1 to run against Docker")
	}
	lokiImage := env("LOKI_IMAGE", "grafana/loki:3.7.9")
	amImage := env("AM_IMAGE", "prom/alertmanager:v0.35.0")
	major := "3"
	if tag := lokiImage[strings.LastIndex(lokiImage, ":")+1:]; strings.HasPrefix(tag, "2.") {
		major = "2"
	}
	dir := t.TempDir()
	os.Chmod(dir, 0o755)
	lokiPort, grpcPort, mlPort, amPort, amCluster, proxyPort := freePort(t), freePort(t), freePort(t), freePort(t), freePort(t), freePort(t)
	grafanaImage := os.Getenv("GRAFANA_IMAGE")
	grafanaPort := freePort(t)

	// webhook receiver for Alertmanager notifications
	hk := &hook{}
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go http.Serve(hl, hk)
	defer hl.Close()

	write(t, filepath.Join(dir, "rules", tenant, "rules.yaml"), rules)
	write(t, filepath.Join(dir, "loki.yaml"), lokiConfig(major, lokiPort, grpcPort, mlPort, proxyPort))
	write(t, filepath.Join(dir, "am.yml"), fmt.Sprintf(`route:
  receiver: hook
  group_by: [alertname, app, msg]
  group_wait: 1s
  group_interval: 1s
  repeat_interval: 1h
receivers:
  - name: hook
    webhook_configs:
      - url: http://%s/hook
        send_resolved: false
`, hl.Addr()))
	if grafanaImage != "" {
		ds, al := grafanaProvisioning(lokiPort, proxyPort)
		write(t, filepath.Join(dir, "grafana", "datasources", "loki.yaml"), ds)
		write(t, filepath.Join(dir, "grafana", "alerting", "e2e.yaml"), al)
		for _, d := range []string{"dashboards", "plugins", "notifiers"} {
			os.MkdirAll(filepath.Join(dir, "grafana", d), 0o755)
		}
	}
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			os.Chmod(p, 0o755)
		}
		return nil
	})

	bin := filepath.Join(dir, "loki-alert-lines")
	run(t, "go", "build", "-o", bin, "..")

	name := fmt.Sprintf("lal-e2e-%d", time.Now().UnixNano())
	run(t, "docker", "run", "-d", "--name", name+"-am", "--network", "host",
		"-v", dir+"/am.yml:/etc/am.yml:ro", amImage,
		"--config.file=/etc/am.yml", fmt.Sprintf("--web.listen-address=127.0.0.1:%d", amPort),
		fmt.Sprintf("--cluster.listen-address=127.0.0.1:%d", amCluster), "--storage.path=/tmp")
	defer exec.Command("docker", "rm", "-f", name+"-am").Run()
	run(t, "docker", "run", "-d", "--name", name+"-loki", "--network", "host",
		"--tmpfs", "/loki:mode=1777", "-v", dir+":/etc/lal-e2e:ro", lokiImage,
		"-config.file=/etc/lal-e2e/loki.yaml")
	defer func() {
		if t.Failed() {
			out, _ := exec.Command("docker", "logs", "--tail", "60", name+"-loki").CombinedOutput()
			t.Logf("loki logs:\n%s", out)
		}
		exec.Command("docker", "rm", "-f", name+"-loki").Run()
	}()

	grafanaURL := fmt.Sprintf("http://127.0.0.1:%d", grafanaPort)
	if grafanaImage != "" {
		run(t, "docker", "run", "-d", "--name", name+"-grafana", "--network", "host",
			"--tmpfs", "/var/lib/grafana:mode=1777", "-v", dir+":/etc/lal-e2e:ro",
			"-e", "GF_SERVER_HTTP_ADDR=127.0.0.1", "-e", fmt.Sprintf("GF_SERVER_HTTP_PORT=%d", grafanaPort),
			"-e", "GF_SERVER_ROOT_URL="+grafanaURL+"/", "-e", "GF_SECURITY_ADMIN_PASSWORD=admin",
			"-e", "GF_PATHS_PROVISIONING=/etc/lal-e2e/grafana", "-e", "GF_ANALYTICS_REPORTING_ENABLED=false",
			"-e", "GF_ANALYTICS_CHECK_FOR_UPDATES=false", "-e", "GF_ANALYTICS_CHECK_FOR_PLUGIN_UPDATES=false",
			"-e", "GF_PLUGINS_PREINSTALL_DISABLED=true", "-e", "GF_LOG_LEVEL=warn",
			"-e", "GF_LOG_FILTERS=ngalert:info,provisioning:info,ngalert.notifier:debug", grafanaImage)
		defer func() {
			if t.Failed() {
				out, _ := exec.Command("docker", "logs", "--tail", "150", name+"-grafana").CombinedOutput()
				var keep []string
				for _, l := range strings.Split(string(out), "\n") {
					if !strings.Contains(l, "manifest watcher") && !strings.Contains(l, "Skipping migration") {
						keep = append(keep, l)
					}
				}
				t.Logf("grafana logs:\n%s", strings.Join(keep, "\n"))
				for _, path := range []string{"/api/prometheus/grafana/api/v1/rules", "/api/v1/provisioning/contact-points", "/api/v1/provisioning/policies", "/api/alertmanager/grafana/api/v2/alerts"} {
					req, _ := http.NewRequest(http.MethodGet, grafanaURL+path, nil)
					req.SetBasicAuth("admin", "admin")
					if resp, err := http.DefaultClient.Do(req); err == nil {
						b, _ := io.ReadAll(io.LimitReader(resp.Body, 3000))
						resp.Body.Close()
						t.Logf("grafana %s: %d %s", path, resp.StatusCode, b)
					}
				}
			}
			exec.Command("docker", "rm", "-f", name+"-grafana").Run()
		}()
	}

	logf, _ := os.Create(filepath.Join(dir, "proxy.log"))
	pargs := []string{fmt.Sprintf("-listen=127.0.0.1:%d", proxyPort),
		fmt.Sprintf("-alertmanager.url=http://127.0.0.1:%d", amPort),
		fmt.Sprintf("-loki.url=http://127.0.0.1:%d", lokiPort),
		"-rules-refresh=2s", "-cache-ttl=0", "-log.level=debug"}
	if grafanaImage != "" {
		pargs = append(pargs, "-grafana.url="+grafanaURL, "-grafana.username=admin")
	}
	proxy := exec.Command(bin, pargs...)
	proxy.Env = append(os.Environ(), "GRAFANA_PASSWORD=admin")
	proxy.Stdout, proxy.Stderr = logf, logf
	if err := proxy.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		proxy.Process.Kill()
		proxy.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(filepath.Join(dir, "proxy.log"))
			t.Logf("proxy log:\n%s", b)
		}
	}()

	lokiURL := fmt.Sprintf("http://127.0.0.1:%d", lokiPort)
	waitFor(t, 180*time.Second, "Loki ready", func() bool {
		resp, err := http.Get(lokiURL + "/ready")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	waitFor(t, 30*time.Second, "Alertmanager ready", func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/-/ready", amPort))
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})

	if grafanaImage != "" {
		waitFor(t, 180*time.Second, "Grafana ready", func() bool {
			resp, err := http.Get(grafanaURL + "/api/health")
			if err != nil {
				return false
			}
			resp.Body.Close()
			return resp.StatusCode == 200
		})
	}

	now := time.Now()
	ts := func(s int) string { return fmt.Sprint(now.Add(time.Duration(-s) * time.Second).UnixNano()) }
	type stream struct {
		Stream map[string]string `json:"stream"`
		Values [][]string        `json:"values"`
	}
	push := []stream{
		{map[string]string{"job": "e2e", "app": "api"}, [][]string{{ts(9), "ERROR api one"}, {ts(8), "INFO api fine"}, {ts(7), "ERROR api two"}}},
		{map[string]string{"job": "e2e", "app": "worker"}, [][]string{{ts(9), "ERROR worker one"}}},
		{map[string]string{"job": "json", "app": "svc"}, [][]string{
			{ts(9), `{"level":"error","msg":"disk full","n":1}`},
			{ts(8), `{"level":"error","msg":"disk full","n":2}`},
			{ts(7), `{"level":"error","msg":"disk full","n":3}`},
			{ts(6), `{"level":"error","msg":"other","n":4}`},
			{ts(5), `{"level":"info","msg":"disk full","n":5}`},
		}},
		{map[string]string{"job": "lat", "app": "api"}, [][]string{{ts(9), "latency_ms=100 path=/a"}, {ts(8), "latency_ms=900 path=/slow"}, {ts(7), "latency_ms=700 path=/slow2"}}},
		{map[string]string{"job": "raw", "app": "x"}, [][]string{{ts(9), "panic: boom"}}},
	}
	body, _ := json.Marshal(map[string]any{"streams": push})
	req, _ := http.NewRequest(http.MethodPost, lokiURL+"/loki/api/v1/push", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Scope-OrgID", tenant)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("push: %d %s", resp.StatusCode, b)
	}

	key := func(a amAlert) string {
		return a.Labels["alertname"] + "/" + a.Labels["app"] + a.Labels["msg"]
	}
	want := []string{"AppErrors/api", "AppErrors/worker", "JsonErrors/disk full", "SlowRequests/api", "Panics/x"}
	if grafanaImage != "" {
		want = append(want, "GrafanaErrors/api", "GrafanaErrors/worker")
	}
	got := map[string]amAlert{}
	waitFor(t, 240*time.Second, "enriched alerts in Alertmanager", func() bool {
		resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/api/v2/alerts", amPort))
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		var as []amAlert
		if json.NewDecoder(resp.Body).Decode(&as) != nil {
			return false
		}
		for _, a := range as {
			if a.Annotations["log_lines"] != "" || a.Annotations["log_lines_error"] != "" {
				got[key(a)] = a
			}
		}
		for _, k := range want {
			if _, ok := got[k]; !ok {
				return false
			}
		}
		return true
	}, func() {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		t.Logf("enriched alerts seen: %v, want %v", keys, want)
	})
	for k, a := range got {
		t.Logf("%s generatorURL=%q\n  query: %s\n  lines:\n%s\n  error: %s", k, a.GeneratorURL, a.Annotations["log_lines_query"], indent(a.Annotations["log_lines"]), a.Annotations["log_lines_error"])
	}
	if _, ok := got["JsonErrors/other"]; ok {
		t.Errorf("JsonErrors fired for msg=other")
	}
	check := func(k, query string, has, hasNot []string, n int) {
		a := got[k]
		if e := a.Annotations["log_lines_error"]; e != "" {
			t.Errorf("%s: error %s", k, e)
		}
		if query != "" && a.Annotations["log_lines_query"] != query {
			t.Errorf("%s: query %q, want %q", k, a.Annotations["log_lines_query"], query)
		}
		lines := a.Annotations["log_lines"]
		for _, s := range has {
			if !strings.Contains(lines, s) {
				t.Errorf("%s: lines miss %q:\n%s", k, s, lines)
			}
		}
		for _, s := range hasNot {
			if strings.Contains(lines, s) {
				t.Errorf("%s: lines contain %q:\n%s", k, s, lines)
			}
		}
		if c := strings.Count(lines, "\n") + 1; c != n {
			t.Errorf("%s: %d lines, want %d:\n%s", k, c, n, lines)
		}
	}
	check("AppErrors/api", `{job="e2e"} |= "ERROR" | app="api"`, []string{"ERROR api one", "ERROR api two"}, []string{"INFO", "worker"}, 2)
	check("AppErrors/worker", `{job="e2e"} |= "ERROR" | app="worker"`, []string{"ERROR worker one"}, []string{"api"}, 1)
	check("JsonErrors/disk full", `{job="json"} | json | level="error" | msg="disk full"`, []string{`"n":1`, `"n":2`, `"n":3`}, []string{"other", "info"}, 3)
	check("SlowRequests/api", `{job="lat", app="api"} | logfmt | latency_ms > 500`, []string{"/slow", "/slow2"}, []string{"latency_ms=100"}, 2)
	// Loki 3.x adds service_name and detected_level, which become filters too.
	check("Panics/x", "", []string{"panic: boom"}, nil, 1)
	if q := got["Panics/x"].Annotations["log_lines_query"]; !strings.HasPrefix(q, `{job="raw"} |= "panic" | app="x"`) || !strings.Contains(q, `| job="raw"`) || strings.Contains(q, "team") {
		t.Errorf("Panics/x: query %q", q)
	}
	// the proxy must have read the expressions from the generator URLs
	mresp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", proxyPort))
	if err != nil {
		t.Fatal(err)
	}
	mb, _ := io.ReadAll(mresp.Body)
	mresp.Body.Close()
	metrics := string(mb)
	t.Logf("proxy metrics:\n%s", metrics)
	if !strings.Contains(metrics, `query_source_total{source="ruler_api"} 0`) || strings.Contains(metrics, `query_source_total{source="generator_url"} 0`) {
		t.Errorf("expressions did not come from the generator URL")
	}
	if grafanaImage != "" && strings.Contains(metrics, `query_source_total{source="grafana_api"} 0`) {
		t.Errorf("no query came from the Grafana API")
	}
	if grafanaImage != "" {
		check("GrafanaErrors/api", `{job="e2e"} |= "ERROR" | app="api"`, []string{"ERROR api one", "ERROR api two"}, []string{"INFO", "worker"}, 2)
		check("GrafanaErrors/worker", `{job="e2e"} |= "ERROR" | app="worker"`, []string{"ERROR worker one"}, []string{"api"}, 1)
	}
	if s := got["AppErrors/api"].Annotations["summary"]; s != "errors in api" {
		t.Errorf("rule annotation lost: %q", s)
	}

	// the notification that reaches a receiver carries the lines
	waitFor(t, 30*time.Second, "webhook notification", func() bool {
		hk.mu.Lock()
		defer hk.mu.Unlock()
		for _, a := range hk.alerts {
			ann, _ := a["annotations"].(map[string]any)
			if s, _ := ann["log_lines"].(string); strings.Contains(s, "ERROR api two") {
				return true
			}
		}
		return false
	})
}

func indent(s string) string {
	return "    " + strings.ReplaceAll(s, "\n", "\n    ")
}

func waitFor(t *testing.T, d time.Duration, what string, f func() bool, onFail ...func()) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(time.Second)
	}
	for _, g := range onFail {
		g()
	}
	t.Fatalf("timeout after %s waiting for %s", d, what)
}
