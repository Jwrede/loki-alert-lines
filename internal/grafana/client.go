// Package grafana reads Grafana-managed alert rules and data sources.
package grafana

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

// Client talks to the Grafana HTTP API.
type Client struct {
	BaseURL  string
	Username string
	Password string
	Token    string
	HTTP     *http.Client
}

// Query is one entry of a rule's data list.
type Query struct {
	RefID             string `json:"refId"`
	DatasourceUID     string `json:"datasourceUid"`
	RelativeTimeRange struct {
		From int64 `json:"from"`
		To   int64 `json:"to"`
	} `json:"relativeTimeRange"`
	Model struct {
		Expr string `json:"expr"`
	} `json:"model"`
}

// Rule is a Grafana-managed alert rule from the provisioning API.
type Rule struct {
	UID       string            `json:"uid"`
	Title     string            `json:"title"`
	Condition string            `json:"condition"`
	Data      []Query           `json:"data"`
	Labels    map[string]string `json:"labels"`
}

// Datasource is the part of a data source the proxy needs.
type Datasource struct {
	UID  string `json:"uid"`
	Type string `json:"type"`
	Name string `json:"name"`
}

var ruleURLRe = regexp.MustCompile(`/alerting/grafana/([^/?#]+)/view`)

// RuleUIDFromURL returns the rule UID of a Grafana generator URL
// (<root>/alerting/grafana/<uid>/view?orgId=1), or "".
func RuleUIDFromURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		return ""
	}
	m := ruleURLRe.FindStringSubmatch(u.EscapedPath())
	if m == nil {
		return ""
	}
	uid, err := url.PathUnescape(m[1])
	if err != nil {
		return ""
	}
	return uid
}

// SetAuth adds the configured credentials to a request.
func (c *Client) SetAuth(req *http.Request) {
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	} else if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	c.SetAuth(req)
	req.Header.Set("Accept", "application/json")
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		return fmt.Errorf("grafana %s: HTTP %d: %s", path, resp.StatusCode, msg)
	}
	return json.Unmarshal(body, out)
}

// Rule fetches an alert rule by UID.
func (c *Client) Rule(ctx context.Context, uid string) (*Rule, error) {
	var r Rule
	if err := c.get(ctx, "/api/v1/provisioning/alert-rules/"+url.PathEscape(uid), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Datasource fetches a data source by UID.
func (c *Client) Datasource(ctx context.Context, uid string) (*Datasource, error) {
	var d Datasource
	if err := c.get(ctx, "/api/datasources/uid/"+url.PathEscape(uid), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// ProxyURL is the base URL of the Grafana data source proxy for a Loki data
// source. Loki API paths can be appended to it.
func (c *Client) ProxyURL(dsUID string) string {
	return strings.TrimRight(c.BaseURL, "/") + "/api/datasources/proxy/uid/" + url.PathEscape(dsUID)
}
