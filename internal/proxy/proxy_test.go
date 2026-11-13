package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Jwrede/loki-alert-lines/internal/grafana"
	"github.com/Jwrede/loki-alert-lines/internal/loki"
)

var now = time.Date(2026, 11, 13, 6, 0, 0, 0, time.UTC)

// fakeLoki serves query_range and the rules API and records requests.
type fakeLoki struct {
	mu      sync.Mutex
	queries []url.Values
	tenants []string
	rules   string
	fail    bool
	srv     *httptest.Server
}

func newFakeLoki(t *testing.T) *fakeLoki {
	f := &fakeLoki{rules: `{"status":"success","data":{"groups":[{"name":"g","rules":[
		{"name":"Errors","query":"sum by (app) (count_over_time({job=\"e2e\"} |= \"ERROR\" [1m])) > 0","labels":{"severity":"page"},"type":"alerting"}]}]}}`}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.tenants = append(f.tenants, r.Header.Get("X-Scope-OrgID"))
		f.mu.Unlock()
		switch r.URL.Path {
		case "/prometheus/api/v1/rules":
			io.WriteString(w, f.rules)
		case "/loki/api/v1/query_range":
			f.mu.Lock()
			f.queries = append(f.queries, r.URL.Query())
			fail := f.fail
			f.mu.Unlock()
			if fail {
				http.Error(w, "parse error at line 1", http.StatusBadRequest)
				return
			}
			body := map[string]any{"status": "success", "data": map[string]any{"resultType": "streams", "result": []any{
				map[string]any{"stream": map[string]string{"app": "api"}, "values": [][]string{
					{itoa(now.Add(-10 * time.Second).UnixNano()), "ERROR second"},
					{itoa(now.Add(-20 * time.Second).UnixNano()), "ERROR first"},
				}},
				map[string]any{"stream": map[string]string{"app": "api", "pod": "b"}, "values": [][]string{
					{itoa(now.Add(-15 * time.Second).UnixNano()), "ERROR middle"},
				}},
			}}}
			json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

type sink struct {
	mu      sync.Mutex
	bodies  [][]Alert
	headers []http.Header
	status  int
	srv     *httptest.Server
}

func newSink(t *testing.T, status int) *sink {
	s := &sink{status: status}
	s.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/prefix/api/v2/alerts" {
			http.NotFound(w, r)
			return
		}
		var a []Alert
		json.NewDecoder(r.Body).Decode(&a)
		s.mu.Lock()
		s.bodies = append(s.bodies, a)
		s.headers = append(s.headers, r.Header.Clone())
		s.mu.Unlock()
		w.WriteHeader(s.status)
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func newProxy(f *fakeLoki, ups ...string) *Proxy {
	return New(Config{
		Upstreams: ups, Loki: &loki.Client{BaseURL: f.srv.URL},
		ForwardAuth: true, ForwardTenant: true,
		Now: func() time.Time { return now }, Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func post(t *testing.T, h http.Handler, path, tenant string, alerts []Alert) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(alerts)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	if tenant != "" {
		req.Header.Set("X-Scope-OrgID", tenant)
	}
	req.Header.Set("Authorization", "Basic cnVsZXI6c2VjcmV0")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func genURL(expr string) string {
	return "http://loki.example/graph?g0.expr=" + url.QueryEscape(expr) + "&g0.tab=1"
}

const ruleExpr = `sum by (app) (count_over_time({job="e2e"} |= "ERROR" [1m])) > 0`

func TestEnrichAndForward(t *testing.T) {
	f := newFakeLoki(t)
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	alerts := []Alert{{
		Labels:       map[string]string{"alertname": "Errors", "app": "api", "severity": "page"},
		Annotations:  map[string]string{"summary": "errors"},
		StartsAt:     now.Add(-30 * time.Second).Format(time.RFC3339Nano),
		EndsAt:       now.Add(3 * time.Minute).Format(time.RFC3339Nano),
		GeneratorURL: genURL(ruleExpr),
	}}
	rec := post(t, p, "/api/v2/alerts", "team-a", alerts)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(s.bodies) != 1 {
		t.Fatalf("forwarded %d times", len(s.bodies))
	}
	got := s.bodies[0][0].Annotations
	wantQ := `{job="e2e"} |= "ERROR" | app="api"`
	if got[AnnQuery] != wantQ {
		t.Errorf("query = %q, want %q", got[AnnQuery], wantQ)
	}
	wantLines := "2026-11-13T05:59:40Z ERROR first\n2026-11-13T05:59:45Z ERROR middle\n2026-11-13T05:59:50Z ERROR second"
	if got[AnnLines] != wantLines {
		t.Errorf("lines =\n%s\nwant\n%s", got[AnnLines], wantLines)
	}
	if got["summary"] != "errors" {
		t.Errorf("existing annotation lost")
	}
	q := f.queries[0]
	if q.Get("direction") != "backward" || q.Get("limit") != "10" {
		t.Errorf("query params %v", q)
	}
	// window: startsAt - range .. now
	if q.Get("start") != itoa(now.Add(-90*time.Second).UnixNano()) || q.Get("end") != itoa(now.UnixNano()) {
		t.Errorf("window %s..%s", q.Get("start"), q.Get("end"))
	}
	for _, tn := range f.tenants {
		if tn != "team-a" {
			t.Errorf("tenant on Loki call = %q", tn)
		}
	}
	h := s.headers[0]
	if h.Get("X-Scope-OrgID") != "team-a" || h.Get("Authorization") != "Basic cnVsZXI6c2VjcmV0" {
		t.Errorf("headers not passed on: %v", h)
	}
}

func TestStaticLabelsWithoutByComeFromRulerAPI(t *testing.T) {
	f := newFakeLoki(t)
	f.rules = `{"data":{"groups":[{"rules":[{"name":"Raw","query":"count_over_time({job=\"e2e\"}[5m]) > 0","labels":{"severity":"page","team":"core"},"type":"alerting"}]}]}}`
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	post(t, p, "/api/v1/alerts", "", []Alert{{
		Labels:       map[string]string{"alertname": "Raw", "job": "e2e", "app": "api", "severity": "page", "team": "core"},
		GeneratorURL: genURL(`count_over_time({job="e2e"}[5m]) > 0`),
	}})
	got := s.bodies[0][0].Annotations[AnnQuery]
	if want := `{job="e2e"} | app="api" | job="e2e"`; got != want {
		t.Errorf("query = %q, want %q", got, want)
	}
}

func TestRuleFallbackWhenGeneratorURLEmpty(t *testing.T) {
	f := newFakeLoki(t)
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	post(t, p, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "Errors", "app": "w", "severity": "page"}}})
	got := s.bodies[0][0].Annotations
	if got[AnnQuery] != `{job="e2e"} |= "ERROR" | app="w"` || got[AnnLines] == "" {
		t.Errorf("annotations = %v", got)
	}
}

func TestQueryAnnotationWins(t *testing.T) {
	f := newFakeLoki(t)
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	post(t, p, "/api/v2/alerts", "", []Alert{{
		Labels:       map[string]string{"alertname": "Slow", "app": "api"},
		Annotations:  map[string]string{"logs_query": `{job="lat", app="api"} | logfmt | latency_ms > 500`, AnnLimit: "2"},
		GeneratorURL: genURL(`max by (app) (max_over_time({job="lat"} | logfmt | unwrap latency_ms [2m])) > 500`),
	}})
	got := s.bodies[0][0].Annotations
	if got[AnnQuery] != `{job="lat", app="api"} | logfmt | latency_ms > 500` {
		t.Errorf("query = %q", got[AnnQuery])
	}
	if _, ok := got[AnnLimit]; ok {
		t.Errorf("log_lines_limit should be consumed")
	}
	if f.queries[0].Get("limit") != "2" {
		t.Errorf("limit = %s", f.queries[0].Get("limit"))
	}
	if strings.Count(got[AnnLines], "\n") != 1 {
		t.Errorf("want 2 lines, got %q", got[AnnLines])
	}
}

func TestResolvedAndOptOutPassThrough(t *testing.T) {
	f := newFakeLoki(t)
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	post(t, p, "/api/v2/alerts", "", []Alert{
		{Labels: map[string]string{"alertname": "Errors", "app": "api"}, EndsAt: now.Add(-time.Second).Format(time.RFC3339Nano), GeneratorURL: genURL(ruleExpr)},
		{Labels: map[string]string{"alertname": "Errors", "app": "x"}, Annotations: map[string]string{AnnLimit: "0"}, GeneratorURL: genURL(ruleExpr)},
	})
	if len(f.queries) != 0 {
		t.Errorf("queried Loki %d times", len(f.queries))
	}
	for _, a := range s.bodies[0] {
		if a.Annotations[AnnLines] != "" || a.Annotations[AnnError] != "" {
			t.Errorf("unexpected annotations %v", a.Annotations)
		}
	}
}

func TestLokiErrorStillForwards(t *testing.T) {
	f := newFakeLoki(t)
	f.fail = true
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	rec := post(t, p, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "Errors", "app": "api"}, GeneratorURL: genURL(ruleExpr)}})
	if rec.Code != 200 || len(s.bodies) != 1 {
		t.Fatalf("code %d, forwarded %d", rec.Code, len(s.bodies))
	}
	if e := s.bodies[0][0].Annotations[AnnError]; !strings.Contains(e, "HTTP 400") {
		t.Errorf("error annotation = %q", e)
	}
}

func TestUnparsableExpressionReported(t *testing.T) {
	f := newFakeLoki(t)
	f.rules = `{"data":{"groups":[]}}`
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	post(t, p, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "V"}, GeneratorURL: genURL(`vector(1) > 0`)}})
	if e := s.bodies[0][0].Annotations[AnnError]; !strings.Contains(e, "no stream selector") {
		t.Errorf("error = %q", e)
	}
}

func TestOneUpstreamDownIsOK(t *testing.T) {
	f := newFakeLoki(t)
	good := newSink(t, 200)
	bad := newSink(t, 500)
	p := newProxy(f, bad.srv.URL+"/prefix", good.srv.URL+"/prefix")
	rec := post(t, p, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "Errors", "app": "api"}, GeneratorURL: genURL(ruleExpr)}})
	if rec.Code != 200 {
		t.Fatalf("code %d", rec.Code)
	}
	p2 := newProxy(f, bad.srv.URL+"/prefix")
	rec = post(t, p2, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "Errors", "app": "api"}, GeneratorURL: genURL(ruleExpr)}})
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("all upstreams down: code %d", rec.Code)
	}
}

func TestCacheDedupesHARulers(t *testing.T) {
	f := newFakeLoki(t)
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	p.cfg.CacheTTL = time.Minute
	a := Alert{Labels: map[string]string{"alertname": "Errors", "app": "api"}, StartsAt: now.Add(-time.Minute).Format(time.RFC3339Nano), GeneratorURL: genURL(ruleExpr)}
	post(t, p, "/api/v2/alerts", "", []Alert{a})
	post(t, p, "/api/v2/alerts", "", []Alert{a})
	if len(f.queries) != 1 {
		t.Errorf("queries = %d, want 1", len(f.queries))
	}
}

func TestFormatLimits(t *testing.T) {
	var lines []loki.Line
	for i := 0; i < 5; i++ {
		lines = append(lines, loki.Line{Time: now.Add(-time.Duration(i) * time.Second), Line: strings.Repeat("é", 30) + "\n"})
	}
	out := FormatLines(lines, 21, 120)
	rows := strings.Split(out, "\n")
	if !strings.HasSuffix(rows[len(rows)-1], "more lines not shown)") {
		t.Fatalf("no trailing note: %q", out)
	}
	if !strings.HasSuffix(rows[0], "...") || strings.Contains(rows[0], "�") {
		t.Errorf("bad truncation %q", rows[0])
	}
	if FormatLines(nil, 10, 10) != "(no matching log lines)" {
		t.Errorf("empty")
	}
}

func TestWindowCappedByMaxWindow(t *testing.T) {
	d := Derived{Range: 5 * time.Minute}
	start, end := d.window(now.Add(-48*time.Hour).Format(time.RFC3339), now, time.Hour)
	if end != now || start != now.Add(-time.Hour) {
		t.Errorf("window %s..%s", start, end)
	}
}

func TestExploreURL(t *testing.T) {
	u := ExploreURL("https://grafana.example/", "loki-uid", `{app="a"}`, now.Add(-time.Minute), now)
	pu, err := url.Parse(u)
	if err != nil || pu.Path != "/explore" {
		t.Fatalf("%s %v", u, err)
	}
	var panes map[string]map[string]any
	if err := json.Unmarshal([]byte(pu.Query().Get("panes")), &panes); err != nil {
		t.Fatal(err)
	}
	if panes["a"]["datasource"] != "loki-uid" {
		t.Errorf("panes %v", panes)
	}
}

func TestMetricsAndHealth(t *testing.T) {
	f := newFakeLoki(t)
	p := newProxy(f, "http://127.0.0.1:1")
	for _, path := range []string{"/-/healthy", "/metrics"} {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != 200 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v2/alerts", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET alerts: %d", rec.Code)
	}
}

func TestExprFromGeneratorURL(t *testing.T) {
	expr := `sum by (app)(count_over_time({job="e2e"} |= "ERROR"[1m])) > 0`
	// as written by Loki 3.7.9
	left := "http://loki.example/explore?left=" + url.QueryEscape(`{"queries":[{"expr":"(`+strings.ReplaceAll(expr, `"`, `\"`)+`)","queryType":"range"}]}`)
	panes := "http://grafana/explore?panes=" + url.QueryEscape(`{"x1":{"queries":[{"expr":"`+strings.ReplaceAll(expr, `"`, `\"`)+`"}]}}`)
	for name, u := range map[string]string{"g0": genURL(expr), "left": left, "panes": panes} {
		got := ExprFromGeneratorURL(u)
		if strings.Trim(got, "()") != strings.Trim(expr, "()") && got != "("+expr+")" {
			t.Errorf("%s: got %q", name, got)
		}
	}
	for _, u := range []string{"", "http://x/graph", "http://x/explore?left=notjson", "%zz"} {
		if got := ExprFromGeneratorURL(u); got != "" {
			t.Errorf("%q: got %q", u, got)
		}
	}
}

func TestLoki3GeneratorURLWithoutRulerAPI(t *testing.T) {
	f := newFakeLoki(t)
	f.rules = `{"data":{"groups":[]}}`
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	left := "http://loki.example/explore?left=" + url.QueryEscape(`{"queries":[{"expr":"(sum by (app)(count_over_time({job=\"e2e\"} |= \"ERROR\"[1m])) > 0)","queryType":"range"}]}`)
	post(t, p, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "Errors", "app": "api", "severity": "page"}, GeneratorURL: left}})
	if got := s.bodies[0][0].Annotations[AnnQuery]; got != `{job="e2e"} |= "ERROR" | app="api"` {
		t.Errorf("query = %q", got)
	}
}

func TestGrafanaManagedAlert(t *testing.T) {
	f := newFakeLoki(t)
	var mu sync.Mutex
	var paths []string
	var auths []string
	g := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		switch {
		case r.URL.Path == "/api/v1/provisioning/alert-rules/rule-1":
			io.WriteString(w, `{"uid":"rule-1","title":"GrafanaErrors","condition":"C","labels":{"severity":"ticket"},"data":[
				{"refId":"A","datasourceUid":"loki-ds","relativeTimeRange":{"from":600,"to":0},"model":{"expr":"sum by (app) (count_over_time({job=\"e2e\"} |= \"ERROR\" [$__auto]))","refId":"A"}},
				{"refId":"B","datasourceUid":"__expr__","model":{"type":"reduce"}},
				{"refId":"C","datasourceUid":"__expr__","model":{"type":"threshold"}}]}`)
		case r.URL.Path == "/api/datasources/uid/loki-ds":
			io.WriteString(w, `{"uid":"loki-ds","type":"loki","name":"Loki"}`)
		case strings.HasPrefix(r.URL.Path, "/api/datasources/proxy/uid/loki-ds/"):
			// hand the Loki API call to the fake Loki
			req, _ := http.NewRequest(r.Method, f.srv.URL+strings.TrimPrefix(r.URL.Path, "/api/datasources/proxy/uid/loki-ds")+"?"+r.URL.RawQuery, nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Error(err)
				return
			}
			defer resp.Body.Close()
			io.Copy(w, resp.Body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer g.Close()
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	p.cfg.Loki = nil // Grafana alerts must not need a direct Loki URL
	p.cfg.Grafana = &grafana.Client{BaseURL: g.URL, Token: "sa-token"}
	p.cfg.GrafanaURL = g.URL
	alert := Alert{
		Labels:       map[string]string{"alertname": "GrafanaErrors", "app": "api", "severity": "ticket", "grafana_folder": "e2e"},
		StartsAt:     now.Add(-time.Minute).Format(time.RFC3339Nano),
		EndsAt:       "0001-01-01T00:00:00Z", // as sent by Grafana 13.3.1 for a firing alert
		GeneratorURL: g.URL + "/alerting/grafana/rule-1/view?orgId=1",
	}
	post(t, p, "/api/v2/alerts", "", []Alert{alert, alert})
	for _, a := range s.bodies[0] {
		ann := a.Annotations
		if ann[AnnError] != "" {
			t.Fatalf("error: %s", ann[AnnError])
		}
		if ann[AnnQuery] != `{job="e2e"} |= "ERROR" | app="api"` {
			t.Errorf("query = %q", ann[AnnQuery])
		}
		if !strings.Contains(ann[AnnLines], "ERROR first") {
			t.Errorf("lines = %q", ann[AnnLines])
		}
		if !strings.Contains(ann[AnnURL], "loki-ds") {
			t.Errorf("explore url = %q", ann[AnnURL])
		}
	}
	// $__auto: the window comes from relativeTimeRange (600 s before startsAt)
	if q := f.queries[0]; q.Get("start") != itoa(now.Add(-11*time.Minute).UnixNano()) {
		t.Errorf("start = %s", q.Get("start"))
	}
	rules := 0
	for i, pth := range paths {
		if auths[i] != "Bearer sa-token" {
			t.Errorf("%s without token", pth)
		}
		if strings.HasPrefix(pth, "/api/v1/provisioning/") {
			rules++
		}
	}
	if rules != 1 {
		t.Errorf("rule fetched %d times, want 1 (cached)", rules)
	}
}

func TestGrafanaAlertWithoutGrafanaConfig(t *testing.T) {
	f := newFakeLoki(t)
	s := newSink(t, 200)
	p := newProxy(f, s.srv.URL+"/prefix")
	post(t, p, "/api/v2/alerts", "", []Alert{{Labels: map[string]string{"alertname": "G"}, GeneratorURL: "http://g/alerting/grafana/x/view"}})
	if e := s.bodies[0][0].Annotations[AnnError]; !strings.Contains(e, "-grafana.url") {
		t.Errorf("error = %q", e)
	}
}
