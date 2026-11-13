package grafana

import "testing"

func TestRuleUIDFromURL(t *testing.T) {
	for in, want := range map[string]string{
		"http://grafana:3000/alerting/grafana/abc-123/view?orgId=1": "abc-123",
		"https://g.example/sub/alerting/grafana/a%2Fb/view":         "a/b",
		"http://loki.example/explore?left=%7B%7D":                   "",
		"http://prom/graph?g0.expr=up":                              "",
		"":                                                          "",
	} {
		if got := RuleUIDFromURL(in); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
