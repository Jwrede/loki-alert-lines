package logql

import (
	"reflect"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	cases := []struct {
		name   string
		expr   string
		sel    string
		rng    time.Duration
		offset time.Duration
		by     []string
	}{
		{"count", `count_over_time({app="api"} |= "ERROR" [5m]) > 0`, `{app="api"} |= "ERROR"`, 5 * time.Minute, 0, nil},
		{"sum by", `sum by (app, level) (rate({job="x"} | json | level=~"err.*" [1m])) > 1`, `{job="x"} | json | level=~"err.*"`, time.Minute, 0, []string{"app", "level"}},
		{"by after", `sum(count_over_time({job="x"}[10m])) by (pod) > 5`, `{job="x"}`, 10 * time.Minute, 0, []string{"pod"}},
		{"without", `sum without (pod) (count_over_time({job="x"}[1m]))`, `{job="x"}`, time.Minute, 0, nil},
		{"unwrap", `max_over_time({job="lat"} | logfmt | unwrap latency_ms | __error__="" [2m]) by (app) > 500`, `{job="lat"} | logfmt`, 2 * time.Minute, 0, []string{"app"}},
		{"unwrap duration", `quantile_over_time(0.99, {job="lat"} | json | unwrap duration(took) [1m]) by (route)`, `{job="lat"} | json`, time.Minute, 0, []string{"route"}},
		{"brackets in string", `count_over_time({app="a"} |~ "\\[ERROR\\]" | line_format "{{.msg}} [x]" [30s])`, `{app="a"} |~ "\\[ERROR\\]" | line_format "{{.msg}} [x]"`, 30 * time.Second, 0, nil},
		{"backticks", "count_over_time({app=\"a\"} |~ `[0-9]+ ms` [1h])", "{app=\"a\"} |~ `[0-9]+ ms`", time.Hour, 0, nil},
		{"braces in selector string", `count_over_time({app="a}b"} [1m])`, `{app="a}b"}`, time.Minute, 0, nil},
		{"ip filter", `count_over_time({job="n"} | logfmt | addr = ip("10.0.0.0/8") [5m])`, `{job="n"} | logfmt | addr = ip("10.0.0.0/8")`, 5 * time.Minute, 0, nil},
		{"offset", `count_over_time({app="a"}[5m] offset 1h) > 0`, `{app="a"}`, 5 * time.Minute, time.Hour, nil},
		{"parenthesized log expr", `count_over_time(({app="a"} |= "x")[1m])`, `{app="a"} |= "x"`, time.Minute, 0, nil},
		{"label_replace", `label_replace(sum by (host) (count_over_time({app="a"}[1m])), "h", "$1", "host", "(.*)")`, `{app="a"}`, time.Minute, 0, []string{"host"}},
		{"plain log query", `{app="a"} |= "x"`, `{app="a"} |= "x"`, 0, 0, nil},
		{"pattern stage", "sum by (message) (count_over_time({app=\"a\"} | pattern `<_> <message>` [1h])) > 0", "{app=\"a\"} | pattern `<_> <message>`", time.Hour, 0, []string{"message"}},
		{"unwrap as label name kept", `count_over_time({app="a"} | json | unwrapped="1" [1m])`, `{app="a"} | json | unwrapped="1"`, time.Minute, 0, nil},
		{"grafana variable range", `sum by (app) (count_over_time({job="e2e"} |= "ERROR" [$__auto]))`, `{job="e2e"} |= "ERROR"`, 0, 0, []string{"app"}},
		{"pattern line filter", "count_over_time({app=\"a\"} |> \"<_> error <_>\" [1m])", "{app=\"a\"} |> \"<_> error <_>\"", time.Minute, 0, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(c.expr)
			if err != nil {
				t.Fatal(err)
			}
			r := p.Ranges[0]
			if r.Selector != c.sel || r.Range != c.rng || r.Offset != c.offset {
				t.Errorf("got %q %s %s, want %q %s %s", r.Selector, r.Range, r.Offset, c.sel, c.rng, c.offset)
			}
			if !reflect.DeepEqual(p.By, c.by) {
				t.Errorf("by = %v, want %v", p.By, c.by)
			}
		})
	}
}

func TestParseBinaryTwoSelectors(t *testing.T) {
	p, err := Parse(`sum(rate({app="a"} |= "error" [5m])) / sum(rate({app="a"}[5m])) > 0.05`)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Ranges) != 2 || p.Ranges[0].Selector != `{app="a"} |= "error"` || p.Ranges[1].Selector != `{app="a"}` {
		t.Fatalf("ranges = %+v", p.Ranges)
	}
}

func TestParseByEmpty(t *testing.T) {
	p, err := Parse(`sum by () (count_over_time({app="a"}[1m]))`)
	if err != nil {
		t.Fatal(err)
	}
	if p.By == nil || len(p.By) != 0 {
		t.Fatalf("by = %#v, want empty non-nil", p.By)
	}
}

func TestParseErrors(t *testing.T) {
	for _, e := range []string{`vector(1) > 0`, `count_over_time({app="a [1m])`, `count_over_time({app="a"}[1x])`, `count_over_time({app="a"} |= "x [1m])`} {
		if _, err := Parse(e); err == nil {
			t.Errorf("Parse(%q): want error", e)
		}
	}
}

func TestFilterLabels(t *testing.T) {
	alert := map[string]string{"alertname": "A", "app": "api", "severity": "page", "team": "x", "__meta": "y", "empty": "", "bad-name": "z"}
	got := FilterLabels(alert, map[string]string{"severity": "page"}, []string{"team"}, nil)
	if !reflect.DeepEqual(got, map[string]string{"app": "api"}) {
		t.Errorf("got %v", got)
	}
	got = FilterLabels(map[string]string{"alertname": "A", "app": "api", "pod": "p1"}, nil, nil, []string{"pod"})
	if !reflect.DeepEqual(got, map[string]string{"pod": "p1"}) {
		t.Errorf("by: got %v", got)
	}
	got = FilterLabels(map[string]string{"alertname": "A", "app": "api"}, nil, nil, []string{})
	if len(got) != 0 {
		t.Errorf("empty by: got %v", got)
	}
}

func TestLogQueryQuoting(t *testing.T) {
	got := LogQuery(`{app="a"} | json`, map[string]string{"msg": `disk "full" \ now`, "app": "a"})
	want := `{app="a"} | json | app="a" | msg="disk \"full\" \\ now"`
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseDuration(t *testing.T) {
	for s, want := range map[string]time.Duration{"5m": 5 * time.Minute, "1h30m": 90 * time.Minute, "2d": 48 * time.Hour, "500ms": 500 * time.Millisecond, "1.5h": 90 * time.Minute} {
		got, err := ParseDuration(s)
		if err != nil || got != want {
			t.Errorf("%s: got %s %v", s, got, err)
		}
	}
	for _, s := range []string{"", "m", "5", "5x"} {
		if _, err := ParseDuration(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
}
