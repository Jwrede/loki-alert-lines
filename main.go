// Command loki-alert-lines sits between the Loki ruler and Alertmanager and
// adds the log lines behind each alert as annotations.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/Jwrede/loki-alert-lines/internal/grafana"
	"github.com/Jwrede/loki-alert-lines/internal/logql"
	"github.com/Jwrede/loki-alert-lines/internal/loki"
	"github.com/Jwrede/loki-alert-lines/internal/proxy"
)

var version = "dev"

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "derive" {
		os.Exit(deriveCmd(os.Args[2:]))
	}
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "-version" || os.Args[1] == "--version") {
		fmt.Println(version)
		return
	}
	os.Exit(serve(os.Args[1:]))
}

func readSecret(file, env string) (string, error) {
	if file != "" {
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return os.Getenv(env), nil
}

func serve(args []string) int {
	fs := flag.NewFlagSet("loki-alert-lines", flag.ContinueOnError)
	listen := fs.String("listen", ":9097", "address to listen on")
	var ams listFlag
	fs.Var(&ams, "alertmanager.url", "Alertmanager base URL to forward to (repeatable or comma separated)")
	amUser := fs.String("alertmanager.username", "", "basic auth user for Alertmanager (password from -alertmanager.password-file or $ALERTMANAGER_PASSWORD)")
	amPassFile := fs.String("alertmanager.password-file", "", "file with the Alertmanager basic auth password")
	amTokenFile := fs.String("alertmanager.bearer-token-file", "", "file with a bearer token for Alertmanager")
	forwardAuth := fs.Bool("forward-auth", true, "pass the ruler's Authorization header on to Alertmanager when no Alertmanager credentials are set")
	forwardTenant := fs.Bool("forward-tenant", true, "pass the ruler's X-Scope-OrgID header on to Alertmanager")
	lokiURL := fs.String("loki.url", "", "Loki base URL for log queries and the ruler API (required)")
	lokiUser := fs.String("loki.username", "", "basic auth user for Loki (password from -loki.password-file or $LOKI_PASSWORD)")
	lokiPassFile := fs.String("loki.password-file", "", "file with the Loki basic auth password")
	lokiTokenFile := fs.String("loki.bearer-token-file", "", "file with a bearer token for Loki")
	lokiTenant := fs.String("loki.tenant", "", "tenant for Loki calls; default: the X-Scope-OrgID the ruler sent")
	limit := fs.Int("lines", 10, "log lines per alert (rule annotation log_lines_limit overrides)")
	maxLine := fs.Int("max-line-length", 500, "cut log lines after this many bytes")
	maxBytes := fs.Int("max-bytes", 4000, "maximum size of the log_lines annotation")
	defRange := fs.Duration("default-range", 5*time.Minute, "look-back window when the rule has no range")
	maxWindow := fs.Duration("max-window", time.Hour, "never query more than this window")
	qTimeout := fs.Duration("query-timeout", 5*time.Second, "timeout per Loki call")
	fTimeout := fs.Duration("forward-timeout", 10*time.Second, "timeout per Alertmanager call")
	rulesTTL := fs.Duration("rules-refresh", 30*time.Second, "how long to cache the ruler rule list")
	cacheTTL := fs.Duration("cache-ttl", 30*time.Second, "cache identical log queries for this long (0 disables)")
	var ignore listFlag
	fs.Var(&ignore, "ignore-label", "alert label never used as a filter (repeatable or comma separated)")
	queryAnn := fs.String("query-annotation", "logs_query", "rule annotation that sets the log query explicitly")
	grafanaURL := fs.String("grafana.url", "", "Grafana base URL; adds a log_lines_url Explore link")
	grafanaDS := fs.String("grafana.datasource-uid", "", "UID of the Loki data source in Grafana, for Explore links of Loki ruler alerts")
	grafanaUser := fs.String("grafana.username", "", "Grafana user for Grafana-managed alerts (password from -grafana.password-file or $GRAFANA_PASSWORD)")
	grafanaPassFile := fs.String("grafana.password-file", "", "file with the Grafana password")
	grafanaTokenFile := fs.String("grafana.token-file", "", "file with a Grafana service account token (or $GRAFANA_TOKEN)")
	logJSON := fs.Bool("log.json", false, "log as JSON")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	var h slog.Handler = slog.NewTextHandler(os.Stderr, nil)
	if *logJSON {
		h = slog.NewJSONHandler(os.Stderr, nil)
	}
	logger := slog.New(h)
	var err error
	var gc *grafana.Client
	if *grafanaURL != "" {
		gc = &grafana.Client{BaseURL: *grafanaURL, Username: *grafanaUser, HTTP: &http.Client{}}
		if *grafanaUser != "" {
			if gc.Password, err = readSecret(*grafanaPassFile, "GRAFANA_PASSWORD"); err != nil {
				logger.Error("reading Grafana password", "err", err)
				return 2
			}
		}
		if gc.Token, err = readSecret(*grafanaTokenFile, "GRAFANA_TOKEN"); err != nil {
			logger.Error("reading Grafana token", "err", err)
			return 2
		}
		if gc.Username == "" && gc.Token == "" {
			gc = nil // only used for Explore links
		}
	}
	if len(ams) == 0 || (*lokiURL == "" && gc == nil) {
		fmt.Fprintln(os.Stderr, "loki-alert-lines: -alertmanager.url and -loki.url (or Grafana credentials) are required")
		return 2
	}
	var lc *loki.Client
	if *lokiURL != "" {
		lc = &loki.Client{BaseURL: *lokiURL, Username: *lokiUser, Tenant: *lokiTenant, HTTP: &http.Client{}}
		if *lokiUser != "" {
			if lc.Password, err = readSecret(*lokiPassFile, "LOKI_PASSWORD"); err != nil {
				logger.Error("reading Loki password", "err", err)
				return 2
			}
		}
		if *lokiTokenFile != "" {
			if lc.BearerToken, err = readSecret(*lokiTokenFile, ""); err != nil {
				logger.Error("reading Loki token", "err", err)
				return 2
			}
		}
	}
	cfg := proxy.Config{
		Upstreams: ams, Grafana: gc, Limit: *limit, MaxLineLength: *maxLine, MaxBytes: *maxBytes,
		DefaultRange: *defRange, MaxWindow: *maxWindow, QueryTimeout: *qTimeout, ForwardTimeout: *fTimeout,
		RulesTTL: *rulesTTL, CacheTTL: *cacheTTL, IgnoreLabels: ignore, QueryAnnotation: *queryAnn,
		GrafanaURL: *grafanaURL, GrafanaDS: *grafanaDS, ForwardAuth: *forwardAuth, ForwardTenant: *forwardTenant,
		UpstreamUser: *amUser, Logger: logger,
	}
	if lc != nil {
		cfg.Loki = lc
	}
	if *amUser != "" {
		if cfg.UpstreamPass, err = readSecret(*amPassFile, "ALERTMANAGER_PASSWORD"); err != nil {
			logger.Error("reading Alertmanager password", "err", err)
			return 2
		}
	}
	if *amTokenFile != "" {
		if cfg.UpstreamToken, err = readSecret(*amTokenFile, ""); err != nil {
			logger.Error("reading Alertmanager token", "err", err)
			return 2
		}
	}
	srv := &http.Server{Addr: *listen, Handler: proxy.New(cfg), ReadHeaderTimeout: 10 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	logger.Info("listening", "addr", *listen, "version", version, "loki", *lokiURL, "alertmanagers", ams.String())
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("server", "err", err)
		return 1
	}
	return 0
}

func deriveCmd(args []string) int {
	fs := flag.NewFlagSet("derive", flag.ContinueOnError)
	expr := fs.String("expr", "", "LogQL metric query of the alerting rule")
	var labels, static, ignore listFlag
	fs.Var(&labels, "label", "alert label k=v (repeatable)")
	fs.Var(&static, "static", "static rule label k=v (repeatable); never used as filter")
	fs.Var(&ignore, "ignore-label", "label never used as filter")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *expr == "" {
		fmt.Fprintln(os.Stderr, "derive: -expr is required")
		return 2
	}
	kv := func(l listFlag) (map[string]string, error) {
		m := map[string]string{}
		for _, s := range l {
			k, v, ok := strings.Cut(s, "=")
			if !ok {
				return nil, fmt.Errorf("label %q is not k=v", s)
			}
			m[k] = v
		}
		return m, nil
	}
	al, err := kv(labels)
	if err == nil {
		var st map[string]string
		if st, err = kv(static); err == nil {
			var p *logql.Parsed
			if p, err = logql.Parse(*expr); err == nil {
				f := logql.FilterLabels(al, st, ignore, p.By)
				fmt.Println(logql.LogQuery(p.Ranges[0].Selector, f))
				keys := make([]string, 0, len(f))
				for k := range f {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				grp := "unknown"
				if p.By != nil {
					grp = "by (" + strings.Join(p.By, ", ") + ")"
				}
				fmt.Fprintf(os.Stderr, "range: %s, offset: %s, filters: %s, grouping: %s\n", p.Ranges[0].Range, p.Ranges[0].Offset, strings.Join(keys, ","), grp)
				return 0
			}
		}
	}
	fmt.Fprintln(os.Stderr, "derive:", err)
	return 1
}
