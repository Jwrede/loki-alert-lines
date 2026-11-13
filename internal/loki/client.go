// Package loki is a small client for the Loki query and ruler APIs.
package loki

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Client talks to one Loki (or a Loki-compatible gateway).
type Client struct {
	BaseURL     string
	HTTP        *http.Client
	Username    string
	Password    string
	BearerToken string
	// Tenant overrides the tenant passed per call when not empty.
	Tenant string
}

// Line is one log line with its stream labels.
type Line struct {
	Time   time.Time
	Line   string
	Labels map[string]string
}

// Rule is an alerting rule as returned by /prometheus/api/v1/rules.
type Rule struct {
	Name        string            `json:"name"`
	Query       string            `json:"query"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Type        string            `json:"type"`
}

func (c *Client) do(ctx context.Context, tenant, path string, q url.Values, out any) error {
	u := strings.TrimRight(c.BaseURL, "/") + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	if c.Tenant != "" {
		tenant = c.Tenant
	}
	if tenant != "" {
		req.Header.Set("X-Scope-OrgID", tenant)
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	} else if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("%s: HTTP %d: %s", path, resp.StatusCode, msg)
	}
	return json.Unmarshal(body, out)
}

// QueryLines runs a log query over [start, end] and returns at most limit
// lines, newest first.
func (c *Client) QueryLines(ctx context.Context, tenant, query string, start, end time.Time, limit int) ([]Line, error) {
	q := url.Values{}
	q.Set("query", query)
	q.Set("start", strconv.FormatInt(start.UnixNano(), 10))
	q.Set("end", strconv.FormatInt(end.UnixNano(), 10))
	q.Set("limit", strconv.Itoa(limit))
	q.Set("direction", "backward")
	var resp struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string `json:"resultType"`
			Result     []struct {
				Stream map[string]string `json:"stream"`
				Values [][]string        `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := c.do(ctx, tenant, "/loki/api/v1/query_range", q, &resp); err != nil {
		return nil, err
	}
	if resp.Data.ResultType != "streams" {
		return nil, fmt.Errorf("query returned %q, not log lines; is it a metric query?", resp.Data.ResultType)
	}
	var lines []Line
	for _, s := range resp.Data.Result {
		for _, v := range s.Values {
			if len(v) < 2 {
				continue
			}
			ns, err := strconv.ParseInt(v[0], 10, 64)
			if err != nil {
				continue
			}
			lines = append(lines, Line{Time: time.Unix(0, ns).UTC(), Line: v[1], Labels: s.Stream})
		}
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Time.After(lines[j].Time) })
	if len(lines) > limit {
		lines = lines[:limit]
	}
	return lines, nil
}

// AlertingRules lists the alerting rules of a tenant.
func (c *Client) AlertingRules(ctx context.Context, tenant string) ([]Rule, error) {
	var resp struct {
		Data struct {
			Groups []struct {
				Rules []Rule `json:"rules"`
			} `json:"groups"`
		} `json:"data"`
	}
	q := url.Values{}
	q.Set("type", "alert")
	if err := c.do(ctx, tenant, "/prometheus/api/v1/rules", q, &resp); err != nil {
		return nil, err
	}
	var out []Rule
	for _, g := range resp.Data.Groups {
		for _, r := range g.Rules {
			if r.Type == "" || r.Type == "alerting" {
				out = append(out, r)
			}
		}
	}
	return out, nil
}
