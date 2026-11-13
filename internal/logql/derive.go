// Package logql derives a log query from a LogQL metric query.
//
// It does not implement the full LogQL grammar. It locates the log range
// expressions inside a metric query (stream selector, pipeline, range), drops
// unwrap stages and appends label filters for the labels of one alert
// instance. Strings, nested parentheses and pipeline functions such as ip()
// are respected.
package logql

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LogRange is one log range expression found in a metric query.
type LogRange struct {
	// Selector is the stream selector plus pipeline, without unwrap stages.
	Selector string
	// Range is the duration in brackets, zero for a plain log query.
	Range time.Duration
	// Offset is the offset modifier after the range, if any.
	Offset time.Duration
}

// Parsed holds what Parse found in an expression.
type Parsed struct {
	Ranges []LogRange
	// By lists the labels of the grouping clause when the expression
	// contains exactly one grouping clause and it is a by clause.
	// It is nil when the grouping is unknown.
	By []string
}

var (
	errNoSelector = errors.New("no stream selector found")
	labelNameRe   = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	groupingRe    = regexp.MustCompile(`\b(by|without)\s*\(`)
)

// Parse finds the log range expressions of a LogQL query.
func Parse(expr string) (*Parsed, error) {
	p := &Parsed{}
	i := 0
	for i < len(expr) {
		c := expr[i]
		switch {
		case isQuote(c):
			j, err := skipString(expr, i)
			if err != nil {
				return nil, err
			}
			i = j
		case c == '{':
			r, next, err := parseLogRange(expr, i)
			if err != nil {
				return nil, err
			}
			p.Ranges = append(p.Ranges, r)
			i = next
		default:
			i++
		}
	}
	if len(p.Ranges) == 0 {
		return nil, errNoSelector
	}
	p.By = grouping(expr)
	return p, nil
}

func isQuote(c byte) bool { return c == '"' || c == '\'' || c == '`' }

// skipString returns the index after the string literal starting at i.
func skipString(s string, i int) (int, error) {
	q := s[i]
	j := i + 1
	for j < len(s) {
		if s[j] == '\\' && q != '`' {
			j += 2
			continue
		}
		if s[j] == q {
			return j + 1, nil
		}
		j++
	}
	return 0, fmt.Errorf("unterminated string at offset %d", i)
}

// parseLogRange parses the log expression starting with the '{' at start.
func parseLogRange(s string, start int) (LogRange, int, error) {
	var r LogRange
	// matching '}' of the stream selector
	i := start + 1
	for {
		if i >= len(s) {
			return r, 0, fmt.Errorf("unterminated stream selector at offset %d", start)
		}
		if isQuote(s[i]) {
			j, err := skipString(s, i)
			if err != nil {
				return r, 0, err
			}
			i = j
			continue
		}
		if s[i] == '}' {
			i++
			break
		}
		i++
	}
	// pipeline until '[' or an unbalanced ')' or the end
	depth := 0
	end := len(s)
	rangeAt := -1
loop:
	for i < len(s) {
		c := s[i]
		switch {
		case isQuote(c):
			j, err := skipString(s, i)
			if err != nil {
				return r, 0, err
			}
			i = j
			continue
		case c == '(':
			depth++
		case c == ')':
			if depth == 0 {
				end = i
				// parenthesized log expression: "( {..} |= "x" )[5m]"
				k := skipSpace(s, i+1)
				if k < len(s) && s[k] == '[' {
					rangeAt = k
				}
				break loop
			}
			depth--
		case c == '[' && depth == 0:
			end = i
			rangeAt = i
			break loop
		}
		i++
	}
	r.Selector = stripUnwrap(strings.TrimSpace(s[start:end]))
	next := end
	if rangeAt >= 0 {
		close := strings.IndexByte(s[rangeAt:], ']')
		if close < 0 {
			return r, 0, fmt.Errorf("unterminated range at offset %d", rangeAt)
		}
		body := strings.TrimSpace(s[rangeAt+1 : rangeAt+close])
		if k := strings.IndexByte(body, ':'); k >= 0 { // subquery-like [5m:1m]
			body = body[:k]
		}
		if strings.HasPrefix(body, "$") {
			// Grafana variable such as $__auto or $__interval: unknown here
			body = ""
		}
		if body != "" {
			d, err := ParseDuration(body)
			if err != nil {
				return r, 0, fmt.Errorf("range %q: %w", body, err)
			}
			r.Range = d
		}
		next = rangeAt + close + 1
		k := skipSpace(s, next)
		if strings.HasPrefix(s[k:], "offset") {
			k2 := skipSpace(s, k+len("offset"))
			e := k2
			for e < len(s) && (isDurationChar(s[e])) {
				e++
			}
			if e > k2 {
				if od, err := ParseDuration(s[k2:e]); err == nil {
					r.Offset = od
					next = e
				}
			}
		}
	}
	return r, next, nil
}

func skipSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

func isDurationChar(c byte) bool {
	return (c >= '0' && c <= '9') || c == '.' || strings.IndexByte("smhdwyµun", c) >= 0
}

// stripUnwrap removes the first top-level "| unwrap" stage and everything
// after it. Stages after unwrap only filter conversion errors.
func stripUnwrap(sel string) string {
	depth := 0
	for i := 0; i < len(sel); i++ {
		c := sel[i]
		switch {
		case isQuote(c):
			j, err := skipString(sel, i)
			if err != nil {
				return sel
			}
			i = j - 1
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == '|' && depth == 0:
			if i+1 < len(sel) && strings.IndexByte("=~>", sel[i+1]) >= 0 {
				continue
			}
			k := skipSpace(sel, i+1)
			if strings.HasPrefix(sel[k:], "unwrap") {
				after := k + len("unwrap")
				if after == len(sel) || !isIdentChar(sel[after]) {
					return strings.TrimSpace(sel[:i])
				}
			}
		}
	}
	return sel
}

func isIdentChar(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

// grouping returns the labels of the only by clause, or nil.
func grouping(expr string) []string {
	clean := blankStrings(expr)
	ms := groupingRe.FindAllStringSubmatchIndex(clean, -1)
	if len(ms) != 1 {
		return nil
	}
	m := ms[0]
	if clean[m[2]:m[3]] != "by" {
		return nil
	}
	open := m[1] - 1
	close := strings.IndexByte(clean[open:], ')')
	if close < 0 {
		return nil
	}
	var out []string
	for _, f := range strings.Split(clean[open+1:open+close], ",") {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

// blankStrings replaces string literals and stream selectors with spaces so
// that keyword searches do not match inside them.
func blankStrings(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if isQuote(b[i]) {
			j, err := skipString(s, i)
			if err != nil {
				return string(b)
			}
			for k := i; k < j; k++ {
				b[k] = ' '
			}
			i = j - 1
		}
	}
	return string(b)
}

// FilterLabels returns the labels of an alert that should become label
// filters: all labels except alertname, the rule's static labels and the
// ignored names. When by is not nil, only labels in by are kept.
func FilterLabels(alert map[string]string, static map[string]string, ignore []string, by []string) map[string]string {
	skip := map[string]bool{"alertname": true}
	for k := range static {
		skip[k] = true
	}
	for _, k := range ignore {
		skip[k] = true
	}
	var keep map[string]bool
	if by != nil {
		keep = map[string]bool{}
		for _, k := range by {
			keep[k] = true
		}
	}
	out := map[string]string{}
	for k, v := range alert {
		if skip[k] || v == "" || !labelNameRe.MatchString(k) || strings.HasPrefix(k, "__") {
			continue
		}
		if keep != nil && !keep[k] {
			continue
		}
		out[k] = v
	}
	return out
}

// LogQuery appends label filters to a log selector, in sorted label order.
func LogQuery(selector string, filters map[string]string) string {
	keys := make([]string, 0, len(filters))
	for k := range filters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(selector)
	for _, k := range keys {
		b.WriteString(" | ")
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(strconv.Quote(filters[k]))
	}
	return b.String()
}

// ParseDuration parses Prometheus style durations such as 5m, 1h30m or 2d.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty duration")
	}
	units := map[string]time.Duration{
		"ms": time.Millisecond, "s": time.Second, "m": time.Minute, "h": time.Hour,
		"d": 24 * time.Hour, "w": 7 * 24 * time.Hour, "y": 365 * 24 * time.Hour,
		"us": time.Microsecond, "µs": time.Microsecond, "ns": time.Nanosecond,
	}
	var total time.Duration
	rest := s
	for rest != "" {
		j := 0
		for j < len(rest) && (rest[j] >= '0' && rest[j] <= '9' || rest[j] == '.') {
			j++
		}
		if j == 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		num, err := strconv.ParseFloat(rest[:j], 64)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		rest = rest[j:]
		k := 0
		for k < len(rest) && !(rest[k] >= '0' && rest[k] <= '9') {
			k++
		}
		u, ok := units[rest[:k]]
		if !ok {
			return 0, fmt.Errorf("invalid unit in duration %q", s)
		}
		total += time.Duration(num * float64(u))
		rest = rest[k:]
	}
	return total, nil
}
