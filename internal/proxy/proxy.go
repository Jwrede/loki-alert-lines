// Package proxy receives alerts from the Loki ruler, adds the log lines that
// match each alert as annotations and forwards the alerts to Alertmanager.
package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jwrede/loki-alert-lines/internal/grafana"
	"github.com/Jwrede/loki-alert-lines/internal/logql"
	"github.com/Jwrede/loki-alert-lines/internal/loki"
)

// Annotation names written by the proxy.
const (
	AnnLines    = "log_lines"
	AnnQuery    = "log_lines_query"
	AnnError    = "log_lines_error"
	AnnURL      = "log_lines_url"
	AnnLimit    = "log_lines_limit"
	defaultUA   = "loki-alert-lines"
	maxBodySize = 16 << 20
)

// Alert is the alert format of the Alertmanager v1 and v2 APIs.
type Alert struct {
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     string            `json:"startsAt,omitempty"`
	EndsAt       string            `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// Config configures a Proxy.
type Config struct {
	Upstreams       []string
	Loki            *loki.Client
	Grafana         *grafana.Client
	Limit           int
	MaxLineLength   int
	MaxBytes        int
	DefaultRange    time.Duration
	MaxWindow       time.Duration
	QueryTimeout    time.Duration
	ForwardTimeout  time.Duration
	RulesTTL        time.Duration
	CacheTTL        time.Duration
	IgnoreLabels    []string
	QueryAnnotation string
	GrafanaURL      string
	GrafanaDS       string
	ForwardAuth     bool
	ForwardTenant   bool
	UpstreamUser    string
	UpstreamPass    string
	UpstreamToken   string
	HTTP            *http.Client
	Logger          *slog.Logger
	Now             func() time.Time
}

// Proxy is the HTTP handler.
type Proxy struct {
	cfg Config

	rulesMu sync.Mutex
	rules   map[string]rulesEntry

	cacheMu sync.Mutex
	cache   map[string]cacheEntry

	grafMu  sync.Mutex
	gfetch  sync.Mutex // one rule fetch at a time, so concurrent alerts share it
	grules  map[string]grafRuleEntry
	gdsType map[string]string

	m metrics
}

type rulesEntry struct {
	at    time.Time
	rules []loki.Rule
	err   error
}

type grafRuleEntry struct {
	at   time.Time
	rule *grafana.Rule
}

type cacheEntry struct {
	at    time.Time
	lines []loki.Line
}

type metrics struct {
	received, enriched, skipped, enrichErr  atomic.Int64
	forwardReq, forwardErr, queries, ruleEr atomic.Int64
	queryNanos                              atomic.Int64
	fromGen, fromRule, fromAnn, fromGraf    atomic.Int64
}

// New returns a Proxy with defaults filled in.
func New(cfg Config) *Proxy {
	if cfg.Limit <= 0 {
		cfg.Limit = 10
	}
	if cfg.MaxLineLength <= 0 {
		cfg.MaxLineLength = 500
	}
	if cfg.MaxBytes <= 0 {
		cfg.MaxBytes = 4000
	}
	if cfg.DefaultRange <= 0 {
		cfg.DefaultRange = 5 * time.Minute
	}
	if cfg.MaxWindow <= 0 {
		cfg.MaxWindow = time.Hour
	}
	if cfg.QueryTimeout <= 0 {
		cfg.QueryTimeout = 5 * time.Second
	}
	if cfg.ForwardTimeout <= 0 {
		cfg.ForwardTimeout = 10 * time.Second
	}
	if cfg.RulesTTL <= 0 {
		cfg.RulesTTL = 30 * time.Second
	}
	if cfg.QueryAnnotation == "" {
		cfg.QueryAnnotation = "logs_query"
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Proxy{cfg: cfg, rules: map[string]rulesEntry{}, cache: map[string]cacheEntry{},
		grules: map[string]grafRuleEntry{}, gdsType: map[string]string{}}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/-/healthy" || r.URL.Path == "/-/ready":
		io.WriteString(w, "OK\n")
	case r.URL.Path == "/metrics":
		p.writeMetrics(w)
	case strings.HasSuffix(r.URL.Path, "/api/v2/alerts") || strings.HasSuffix(r.URL.Path, "/api/v1/alerts"):
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		p.handleAlerts(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (p *Proxy) handleAlerts(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(body) > maxBodySize {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}
	var alerts []Alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		http.Error(w, "invalid alerts: "+err.Error(), http.StatusBadRequest)
		return
	}
	tenant := r.Header.Get("X-Scope-OrgID")
	p.m.received.Add(int64(len(alerts)))
	p.EnrichAll(r.Context(), tenant, alerts)
	if err := p.forward(r.Context(), tenant, r.Header.Get("Authorization"), alerts); err != nil {
		p.cfg.Logger.Error("forward failed", "err", err)
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// EnrichAll adds log lines to every firing alert, at most 8 at a time.
func (p *Proxy) EnrichAll(ctx context.Context, tenant string, alerts []Alert) {
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i := range alerts {
		wg.Add(1)
		sem <- struct{}{}
		go func(a *Alert) {
			defer wg.Done()
			defer func() { <-sem }()
			p.enrich(ctx, tenant, a)
		}(&alerts[i])
	}
	wg.Wait()
}

func (p *Proxy) enrich(ctx context.Context, tenant string, a *Alert) {
	now := p.cfg.Now()
	if a.Annotations == nil {
		a.Annotations = map[string]string{}
	}
	ann := a.Annotations
	if a.EndsAt != "" {
		if t, err := time.Parse(time.RFC3339Nano, a.EndsAt); err == nil && !t.After(now) {
			p.m.skipped.Add(1)
			return // resolved
		}
	}
	if ann[AnnLines] != "" {
		p.m.skipped.Add(1)
		return
	}
	limit := p.cfg.Limit
	if v, ok := ann[AnnLimit]; ok {
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err == nil && n >= 0 {
			limit = n
		}
		delete(ann, AnnLimit)
	}
	if limit == 0 {
		p.m.skipped.Add(1)
		return
	}
	q, err := p.Derive(ctx, tenant, a)
	if err != nil {
		p.m.enrichErr.Add(1)
		ann[AnnError] = err.Error()
		return
	}
	start, end := q.window(a.StartsAt, now, p.cfg.MaxWindow)
	lines, err := p.query(ctx, q.Client, tenant, q.Query, start, end, limit)
	ann[AnnQuery] = q.Query
	if err != nil {
		p.m.enrichErr.Add(1)
		ann[AnnError] = err.Error()
		return
	}
	ann[AnnLines] = FormatLines(lines, p.cfg.MaxLineLength, p.cfg.MaxBytes)
	if p.cfg.GrafanaURL != "" {
		ds := p.cfg.GrafanaDS
		if q.DatasourceUID != "" {
			ds = q.DatasourceUID
		}
		ann[AnnURL] = ExploreURL(p.cfg.GrafanaURL, ds, q.Query, start, end)
	}
	p.m.enriched.Add(1)
}

// Derived is the log query for one alert.
type Derived struct {
	Query  string
	Range  time.Duration
	Offset time.Duration
	// Source says where the query came from: annotation, generator_url
	// (expression read from the alert), ruler_api (expression looked up) or
	// grafana_api (Grafana-managed rule).
	Source string
	// Client runs the query; nil means the configured Loki.
	Client *loki.Client
	// DatasourceUID is the Grafana data source of a Grafana-managed rule.
	DatasourceUID string
}

func (d Derived) window(startsAt string, now time.Time, maxWindow time.Duration) (time.Time, time.Time) {
	end := now.Add(-d.Offset)
	start := end.Add(-d.Range)
	if t, err := time.Parse(time.RFC3339Nano, startsAt); err == nil && t.Before(now) {
		start = t.Add(-d.Range - d.Offset)
	}
	if end.Sub(start) > maxWindow {
		start = end.Add(-maxWindow)
	}
	return start, end
}

// Derive works out the log query for an alert.
func (p *Proxy) Derive(ctx context.Context, tenant string, a *Alert) (Derived, error) {
	d := Derived{Range: p.cfg.DefaultRange}
	uid := grafana.RuleUIDFromURL(a.GeneratorURL)
	if uid == "" {
		uid = a.Labels["__alert_rule_uid__"]
	}
	if uid != "" {
		return p.deriveGrafana(ctx, uid, a)
	}
	expr := ExprFromGeneratorURL(a.GeneratorURL)
	rule := p.findRule(ctx, tenant, a.Labels, expr)
	fromRule := false
	if expr == "" && rule != nil {
		expr, fromRule = rule.Query, true
	}
	var parsed *logql.Parsed
	if expr != "" {
		var err error
		parsed, err = logql.Parse(expr)
		if err == nil && parsed.Ranges[0].Range > 0 {
			d.Range = parsed.Ranges[0].Range
			d.Offset = parsed.Ranges[0].Offset
		}
		if err != nil && a.Annotations[p.cfg.QueryAnnotation] == "" {
			return d, fmt.Errorf("cannot derive a log query from %q: %v", expr, err)
		}
	}
	if q := strings.TrimSpace(a.Annotations[p.cfg.QueryAnnotation]); q != "" {
		d.Query, d.Source = q, "annotation"
		p.m.fromAnn.Add(1)
		return d, nil
	}
	if parsed == nil {
		return d, errors.New("no rule expression: generatorURL is empty and no matching rule was found in the Loki ruler API")
	}
	var static map[string]string
	if rule != nil {
		static = rule.Labels
	}
	filters := logql.FilterLabels(a.Labels, static, p.cfg.IgnoreLabels, parsed.By)
	d.Query, d.Source = logql.LogQuery(parsed.Ranges[0].Selector, filters), "generator_url"
	if fromRule {
		d.Source = "ruler_api"
		p.m.fromRule.Add(1)
	} else {
		p.m.fromGen.Add(1)
	}
	return d, nil
}

// ExprFromGeneratorURL extracts the rule expression from a generator URL.
// Prometheus and Loki 2.x use /graph?g0.expr=...; Loki 3.x links to Grafana
// Explore with /explore?left={"queries":[{"expr":...}]}; newer Explore
// links use panes={"<id>":{"queries":[...]}}.
func ExprFromGeneratorURL(s string) string {
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	q := u.Query()
	if e := q.Get("g0.expr"); e != "" {
		return e
	}
	type pane struct {
		Queries []struct {
			Expr string `json:"expr"`
		} `json:"queries"`
	}
	if l := q.Get("left"); l != "" {
		var p pane
		if json.Unmarshal([]byte(l), &p) == nil && len(p.Queries) > 0 {
			return p.Queries[0].Expr
		}
	}
	if ps := q.Get("panes"); ps != "" {
		var m map[string]pane
		if json.Unmarshal([]byte(ps), &m) == nil {
			keys := make([]string, 0, len(m))
			for k := range m {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if len(m[k].Queries) > 0 {
					return m[k].Queries[0].Expr
				}
			}
		}
	}
	return ""
}

func (p *Proxy) deriveGrafana(ctx context.Context, uid string, a *Alert) (Derived, error) {
	d := Derived{Range: p.cfg.DefaultRange, Source: "grafana_api"}
	g := p.cfg.Grafana
	if g == nil {
		return d, errors.New("Grafana-managed alert: set -grafana.url and Grafana credentials to look up its rule")
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	rule, err := p.grafanaRule(cctx, uid)
	if err != nil {
		return d, err
	}
	var q *grafana.Query
	for i := range rule.Data {
		ds := rule.Data[i].DatasourceUID
		if ds == "" || ds == "__expr__" || ds == "-100" {
			continue
		}
		typ, err := p.grafanaDSType(cctx, ds)
		if err != nil {
			return d, err
		}
		if typ == "loki" {
			q = &rule.Data[i]
			break
		}
	}
	if q == nil {
		return d, fmt.Errorf("Grafana rule %s has no Loki query", uid)
	}
	d.DatasourceUID = q.DatasourceUID
	d.Client = &loki.Client{BaseURL: g.ProxyURL(q.DatasourceUID), Username: g.Username, Password: g.Password, BearerToken: g.Token, HTTP: g.HTTP}
	if q.RelativeTimeRange.From > q.RelativeTimeRange.To {
		d.Range = time.Duration(q.RelativeTimeRange.From-q.RelativeTimeRange.To) * time.Second
	}
	parsed, perr := logql.Parse(q.Model.Expr)
	if perr == nil && parsed.Ranges[0].Range > 0 {
		d.Range, d.Offset = parsed.Ranges[0].Range, parsed.Ranges[0].Offset
	}
	p.m.fromGraf.Add(1)
	if o := strings.TrimSpace(a.Annotations[p.cfg.QueryAnnotation]); o != "" {
		d.Query, d.Source = o, "annotation"
		return d, nil
	}
	if perr != nil {
		return d, fmt.Errorf("cannot derive a log query from %q: %v", q.Model.Expr, perr)
	}
	ignore := append([]string{"grafana_folder"}, p.cfg.IgnoreLabels...)
	filters := logql.FilterLabels(a.Labels, rule.Labels, ignore, parsed.By)
	d.Query = logql.LogQuery(parsed.Ranges[0].Selector, filters)
	return d, nil
}

func (p *Proxy) grafanaRule(ctx context.Context, uid string) (*grafana.Rule, error) {
	p.gfetch.Lock()
	defer p.gfetch.Unlock()
	p.grafMu.Lock()
	e, ok := p.grules[uid]
	p.grafMu.Unlock()
	if ok && p.cfg.Now().Sub(e.at) < p.cfg.RulesTTL {
		return e.rule, nil
	}
	r, err := p.cfg.Grafana.Rule(ctx, uid)
	if err != nil {
		p.m.ruleEr.Add(1)
		if ok {
			return e.rule, nil
		}
		return nil, err
	}
	p.grafMu.Lock()
	p.grules[uid] = grafRuleEntry{at: p.cfg.Now(), rule: r}
	p.grafMu.Unlock()
	return r, nil
}

func (p *Proxy) grafanaDSType(ctx context.Context, uid string) (string, error) {
	p.grafMu.Lock()
	t, ok := p.gdsType[uid]
	p.grafMu.Unlock()
	if ok {
		return t, nil
	}
	ds, err := p.cfg.Grafana.Datasource(ctx, uid)
	if err != nil {
		return "", err
	}
	p.grafMu.Lock()
	p.gdsType[uid] = ds.Type
	p.grafMu.Unlock()
	return ds.Type, nil
}

func normalize(s string) string { return strings.Join(strings.Fields(s), "") }

func (p *Proxy) findRule(ctx context.Context, tenant string, labels map[string]string, expr string) *loki.Rule {
	if p.cfg.Loki == nil {
		return nil
	}
	rules := p.rulesFor(ctx, tenant)
	name := labels["alertname"]
	var cands []loki.Rule
	for _, r := range rules {
		if r.Name != name {
			continue
		}
		ok := true
		for k, v := range r.Labels {
			if labels[k] != v {
				ok = false
				break
			}
		}
		if ok {
			cands = append(cands, r)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	if expr != "" {
		for i := range cands {
			if normalize(cands[i].Query) == normalize(expr) {
				return &cands[i]
			}
		}
	}
	return &cands[0]
}

func (p *Proxy) rulesFor(ctx context.Context, tenant string) []loki.Rule {
	p.rulesMu.Lock()
	e, ok := p.rules[tenant]
	p.rulesMu.Unlock()
	if ok && p.cfg.Now().Sub(e.at) < p.cfg.RulesTTL {
		return e.rules
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	rules, err := p.cfg.Loki.AlertingRules(cctx, tenant)
	if err != nil {
		p.m.ruleEr.Add(1)
		p.cfg.Logger.Warn("listing ruler rules failed", "tenant", tenant, "err", err)
		rules = e.rules // keep the stale list
	}
	p.rulesMu.Lock()
	p.rules[tenant] = rulesEntry{at: p.cfg.Now(), rules: rules, err: err}
	p.rulesMu.Unlock()
	return rules
}

func (p *Proxy) query(ctx context.Context, c *loki.Client, tenant, q string, start, end time.Time, limit int) ([]loki.Line, error) {
	if c == nil {
		c = p.cfg.Loki
	}
	if c == nil {
		return nil, errors.New("no Loki URL configured")
	}
	key := fmt.Sprintf("%s\x00%s\x00%s\x00%d\x00%d", c.BaseURL, tenant, q, start.Unix(), limit)
	if p.cfg.CacheTTL > 0 {
		p.cacheMu.Lock()
		e, ok := p.cache[key]
		p.cacheMu.Unlock()
		if ok && p.cfg.Now().Sub(e.at) < p.cfg.CacheTTL {
			return e.lines, nil
		}
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.QueryTimeout)
	defer cancel()
	t0 := time.Now()
	lines, err := c.QueryLines(cctx, tenant, q, start, end, limit)
	p.m.queries.Add(1)
	p.m.queryNanos.Add(int64(time.Since(t0)))
	if err != nil {
		return nil, err
	}
	if p.cfg.CacheTTL > 0 {
		now := p.cfg.Now()
		p.cacheMu.Lock()
		for k, e := range p.cache {
			if now.Sub(e.at) >= p.cfg.CacheTTL {
				delete(p.cache, k)
			}
		}
		p.cache[key] = cacheEntry{at: now, lines: lines}
		p.cacheMu.Unlock()
	}
	return lines, nil
}

// FormatLines renders lines oldest first, one per line, with RFC 3339
// timestamps. Long lines are cut at maxLine bytes; lines that do not fit
// into maxBytes are counted in a trailing note.
func FormatLines(lines []loki.Line, maxLine, maxBytes int) string {
	if len(lines) == 0 {
		return "(no matching log lines)"
	}
	var b strings.Builder
	shown := 0
	for i := len(lines) - 1; i >= 0; i-- {
		l := strings.TrimRight(lines[i].Line, "\r\n")
		l = strings.ReplaceAll(l, "\n", "\\n")
		if len(l) > maxLine {
			l = truncate(l, maxLine) + "..."
		}
		row := lines[i].Time.Format(time.RFC3339Nano) + " " + l
		if b.Len()+len(row)+1 > maxBytes && shown > 0 {
			break
		}
		if shown > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(row)
		shown++
	}
	if rest := len(lines) - shown; rest > 0 {
		fmt.Fprintf(&b, "\n(%d more lines not shown)", rest)
	}
	return b.String()
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

// ExploreURL builds a Grafana Explore link for the query and window.
func ExploreURL(base, dsUID, query string, start, end time.Time) string {
	ds := map[string]string{"type": "loki"}
	if dsUID != "" {
		ds["uid"] = dsUID
	}
	pane := map[string]any{
		"a": map[string]any{
			"datasource": dsUID,
			"queries": []any{map[string]any{
				"refId": "A", "expr": query, "queryType": "range", "datasource": ds,
			}},
			"range": map[string]string{
				"from": strconv.FormatInt(start.UnixMilli(), 10),
				"to":   strconv.FormatInt(end.UnixMilli(), 10),
			},
		},
	}
	js, _ := json.Marshal(pane)
	return strings.TrimRight(base, "/") + "/explore?schemaVersion=1&panes=" + url.QueryEscape(string(js))
}

func (p *Proxy) forward(ctx context.Context, tenant, auth string, alerts []Alert) error {
	if len(p.cfg.Upstreams) == 0 {
		return errors.New("no Alertmanager configured")
	}
	body, err := json.Marshal(alerts)
	if err != nil {
		return err
	}
	type res struct {
		url string
		err error
	}
	ch := make(chan res, len(p.cfg.Upstreams))
	for _, up := range p.cfg.Upstreams {
		go func(up string) {
			ch <- res{up, p.post(ctx, up, tenant, auth, body)}
		}(up)
	}
	var errs []string
	okCount := 0
	for range p.cfg.Upstreams {
		r := <-ch
		p.m.forwardReq.Add(1)
		if r.err != nil {
			p.m.forwardErr.Add(1)
			errs = append(errs, fmt.Sprintf("%s: %v", r.url, r.err))
		} else {
			okCount++
		}
	}
	if okCount == 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	for _, e := range errs {
		p.cfg.Logger.Warn("forward to one Alertmanager failed", "err", e)
	}
	return nil
}

func (p *Proxy) post(ctx context.Context, up, tenant, auth string, body []byte) error {
	cctx, cancel := context.WithTimeout(ctx, p.cfg.ForwardTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(cctx, http.MethodPost, strings.TrimRight(up, "/")+"/api/v2/alerts", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", defaultUA)
	if tenant != "" && p.cfg.ForwardTenant {
		req.Header.Set("X-Scope-OrgID", tenant)
	}
	switch {
	case p.cfg.UpstreamToken != "":
		req.Header.Set("Authorization", "Bearer "+p.cfg.UpstreamToken)
	case p.cfg.UpstreamUser != "":
		req.SetBasicAuth(p.cfg.UpstreamUser, p.cfg.UpstreamPass)
	case auth != "" && p.cfg.ForwardAuth:
		req.Header.Set("Authorization", auth)
	}
	resp, err := p.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (p *Proxy) writeMetrics(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	c := func(name, help string, v int64) {
		fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n%s %d\n", name, help, name, name, v)
	}
	c("loki_alert_lines_alerts_received_total", "Alerts received from the ruler.", p.m.received.Load())
	c("loki_alert_lines_alerts_enriched_total", "Alerts that got log lines.", p.m.enriched.Load())
	c("loki_alert_lines_alerts_skipped_total", "Resolved or opted-out alerts passed through unchanged.", p.m.skipped.Load())
	c("loki_alert_lines_enrich_errors_total", "Alerts forwarded with log_lines_error.", p.m.enrichErr.Load())
	c("loki_alert_lines_rule_list_errors_total", "Failed calls to the Loki ruler API.", p.m.ruleEr.Load())
	c("loki_alert_lines_forward_requests_total", "Requests to Alertmanager.", p.m.forwardReq.Load())
	c("loki_alert_lines_forward_errors_total", "Failed requests to Alertmanager.", p.m.forwardErr.Load())
	c("loki_alert_lines_loki_queries_total", "Log queries sent to Loki.", p.m.queries.Load())
	fmt.Fprintf(w, "# HELP loki_alert_lines_query_source_total Where the log query of an alert came from.\n# TYPE loki_alert_lines_query_source_total counter\n")
	fmt.Fprintf(w, "loki_alert_lines_query_source_total{source=\"annotation\"} %d\n", p.m.fromAnn.Load())
	fmt.Fprintf(w, "loki_alert_lines_query_source_total{source=\"generator_url\"} %d\n", p.m.fromGen.Load())
	fmt.Fprintf(w, "loki_alert_lines_query_source_total{source=\"ruler_api\"} %d\n", p.m.fromRule.Load())
	fmt.Fprintf(w, "loki_alert_lines_query_source_total{source=\"grafana_api\"} %d\n", p.m.fromGraf.Load())
	fmt.Fprintf(w, "# HELP loki_alert_lines_loki_query_seconds_total Time spent in Loki queries.\n# TYPE loki_alert_lines_loki_query_seconds_total counter\nloki_alert_lines_loki_query_seconds_total %g\n",
		float64(p.m.queryNanos.Load())/1e9)
}
