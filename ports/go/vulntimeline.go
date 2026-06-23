// Command vulntimeline (Go port) — defensive vulnerability-disclosure analytics.
//
// A faithful port of the primary Python CLI's core surface: the `metrics` and
// `flags` subcommands. Same advisory JSON input, same remediation windows, same
// risky-pattern flags, and the same `--fail-on-any` CI gate (exit code 2).
//
// Passive / offline / authorized-use only. No network, standard library only.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// AdvisoryError mirrors the Python core's error type.
var ErrAdvisory = errors.New("advisory error")

// dayOrdinal is days since the Unix epoch (UTC), the unit we diff in.
type dayOrdinal int64

func toOrdinal(t time.Time) dayOrdinal {
	u := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	return dayOrdinal(u.Unix() / 86400)
}

var (
	reISODate     = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})$`)
	reISODateTime = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[T ]`)
	reSlashYMD    = regexp.MustCompile(`^(\d{4})/(\d{2})/(\d{2})$`)
	reUSDate      = regexp.MustCompile(`^(\d{2})/(\d{2})/(\d{4})$`)
	reDashDMY     = regexp.MustCompile(`^(\d{2})-(\d{2})-(\d{4})$`)
	reCompact     = regexp.MustCompile(`^(\d{4})(\d{2})(\d{2})$`)
	reSpelled     = regexp.MustCompile(`^([A-Za-z]+)\s+(\d{1,2}),\s*(\d{4})$`)
)

var months = map[string]int{
	"january": 1, "february": 2, "march": 3, "april": 4, "may": 5, "june": 6,
	"july": 7, "august": 8, "september": 9, "october": 10, "november": 11, "december": 12,
	"jan": 1, "feb": 2, "mar": 3, "apr": 4, "jun": 6, "jul": 7, "aug": 8, "sep": 9,
	"oct": 10, "nov": 11, "dec": 12,
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func mkDate(y, m, d int) dayOrdinal {
	return toOrdinal(time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC))
}

// parseDate accepts the same formats as the Python core. nil-equivalent is
// represented by ok=false with no error; an unparsable non-empty value errors.
func parseDate(raw interface{}) (dayOrdinal, bool, error) {
	if raw == nil {
		return 0, false, nil
	}
	s, isStr := raw.(string)
	if !isStr {
		return 0, false, fmt.Errorf("%w: unsupported date type", ErrAdvisory)
	}
	text := strings.TrimSpace(s)
	if text == "" {
		return 0, false, nil
	}
	if m := reISODate.FindStringSubmatch(text); m != nil {
		return mkDate(atoi(m[1]), atoi(m[2]), atoi(m[3])), true, nil
	}
	if m := reISODateTime.FindStringSubmatch(text); m != nil {
		return mkDate(atoi(m[1]), atoi(m[2]), atoi(m[3])), true, nil
	}
	if m := reSlashYMD.FindStringSubmatch(text); m != nil {
		return mkDate(atoi(m[1]), atoi(m[2]), atoi(m[3])), true, nil
	}
	if m := reUSDate.FindStringSubmatch(text); m != nil {
		return mkDate(atoi(m[3]), atoi(m[1]), atoi(m[2])), true, nil
	}
	if m := reDashDMY.FindStringSubmatch(text); m != nil {
		return mkDate(atoi(m[3]), atoi(m[2]), atoi(m[1])), true, nil
	}
	if m := reCompact.FindStringSubmatch(text); m != nil {
		return mkDate(atoi(m[1]), atoi(m[2]), atoi(m[3])), true, nil
	}
	if m := reSpelled.FindStringSubmatch(text); m != nil {
		if mo, ok := months[strings.ToLower(m[1])]; ok {
			return mkDate(atoi(m[3]), mo, atoi(m[2])), true, nil
		}
	}
	return 0, false, fmt.Errorf("%w: could not parse date: %q", ErrAdvisory, s)
}

// Advisory holds parsed milestone dates; presence is tracked per field.
type Advisory struct {
	ID       string
	Title    string
	Severity string
	dates    map[string]dayOrdinal // only present fields are stored
}

func (a *Advisory) date(field string) (dayOrdinal, bool) {
	v, ok := a.dates[field]
	return v, ok
}

func advisoryFromMap(raw map[string]interface{}) (*Advisory, error) {
	idRaw, ok := raw["id"]
	if !ok {
		return nil, fmt.Errorf("%w: missing required 'id'", ErrAdvisory)
	}
	id := strings.TrimSpace(fmt.Sprintf("%v", idRaw))
	if id == "" {
		return nil, fmt.Errorf("%w: missing required 'id'", ErrAdvisory)
	}
	a := &Advisory{ID: id, dates: map[string]dayOrdinal{}}
	if t, ok := raw["title"].(string); ok {
		a.Title = strings.TrimSpace(t)
	}
	if s, ok := raw["severity"].(string); ok {
		a.Severity = strings.ToLower(strings.TrimSpace(s))
	}
	for _, f := range []string{"discovered", "reported", "disclosed", "exploited", "patched"} {
		d, present, err := parseDate(raw[f])
		if err != nil {
			return nil, err
		}
		if present {
			a.dates[f] = d
		}
	}
	return a, nil
}

func loadAdvisories(data []byte) ([]*Advisory, error) {
	var top interface{}
	if err := json.Unmarshal(data, &top); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON: %v", ErrAdvisory, err)
	}
	var records []interface{}
	switch v := top.(type) {
	case []interface{}:
		records = v
	case map[string]interface{}:
		inner, ok := v["advisories"]
		if !ok {
			return nil, fmt.Errorf("%w: JSON object has no 'advisories' key", ErrAdvisory)
		}
		arr, ok := inner.([]interface{})
		if !ok {
			return nil, fmt.Errorf("%w: 'advisories' is not a list", ErrAdvisory)
		}
		records = arr
	default:
		return nil, fmt.Errorf("%w: expected a list of advisory records", ErrAdvisory)
	}
	out := make([]*Advisory, 0, len(records))
	seen := map[string]bool{}
	for _, rec := range records {
		m, ok := rec.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%w: advisory record must be an object", ErrAdvisory)
		}
		a, err := advisoryFromMap(m)
		if err != nil {
			return nil, err
		}
		if seen[a.ID] {
			return nil, fmt.Errorf("%w: duplicate advisory id: %s", ErrAdvisory, a.ID)
		}
		seen[a.ID] = true
		out = append(out, a)
	}
	return out, nil
}

// Window holds the per-advisory remediation metrics. Pointers model "absent".
type Window struct {
	ID                   string
	Severity             string
	TimeToPatch          *int
	DisclosureGap        *int
	ReportLatency        *int
	ExposureWindow       *int
	ExposureOpen         bool
	ExploitedBeforePatch bool
	Unpatched            bool
}

func ptr(v int) *int { return &v }

func daysBetween(a *Advisory, later, earlier string) *int {
	l, lok := a.date(later)
	e, eok := a.date(earlier)
	if !lok || !eok {
		return nil
	}
	return ptr(int(l - e))
}

func advisoryWindows(a *Advisory, today dayOrdinal) Window {
	w := Window{ID: a.ID, Severity: a.Severity}
	w.TimeToPatch = daysBetween(a, "patched", "disclosed")
	w.DisclosureGap = daysBetween(a, "disclosed", "reported")
	w.ReportLatency = daysBetween(a, "reported", "discovered")

	exploited, hasExploit := a.date("exploited")
	patched, hasPatch := a.date("patched")
	w.Unpatched = !hasPatch

	if hasExploit {
		if hasPatch {
			d := int(patched - exploited)
			if d < 0 {
				d = 0
			}
			w.ExposureWindow = ptr(d)
			if exploited < patched {
				w.ExploitedBeforePatch = true
			}
		} else {
			d := int(today - exploited)
			if d < 0 {
				d = 0
			}
			w.ExposureWindow = ptr(d)
			w.ExposureOpen = true
			w.ExploitedBeforePatch = true
		}
	}
	return w
}

func median(vals []int) *float64 {
	if len(vals) == 0 {
		return nil
	}
	s := append([]int(nil), vals...)
	sort.Ints(s)
	mid := len(s) / 2
	var m float64
	if len(s)%2 == 1 {
		m = float64(s[mid])
	} else {
		m = float64(s[mid-1]+s[mid]) / 2
	}
	return &m
}

// Flag is a detected risky pattern.
type Flag struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func detectFlags(advs []*Advisory, maxTTP *int, today dayOrdinal) []Flag {
	flags := []Flag{}
	for _, a := range advs {
		w := advisoryWindows(a, today)
		if w.ExploitedBeforePatch {
			detail := "exploitation observed before a patch was available"
			if w.Unpatched {
				detail = "exploitation observed and advisory remains unpatched"
			}
			flags = append(flags, Flag{a.ID, "exploited_before_patch", "high", detail})
		}
		if maxTTP != nil && w.TimeToPatch != nil && *w.TimeToPatch > *maxTTP {
			flags = append(flags, Flag{a.ID, "slow_patch", "medium",
				fmt.Sprintf("time-to-patch %dd exceeds threshold %dd", *w.TimeToPatch, *maxTTP)})
		}
		if w.Unpatched {
			flags = append(flags, Flag{a.ID, "unpatched", "medium", "no patch date recorded"})
		}
		for _, pair := range [][2]interface{}{
			{"time_to_patch", w.TimeToPatch}, {"disclosure_gap", w.DisclosureGap}, {"report_latency", w.ReportLatency},
		} {
			name := pair[0].(string)
			val := pair[1].(*int)
			if val != nil && *val < 0 {
				flags = append(flags, Flag{a.ID, "negative_window", "low",
					fmt.Sprintf("%s is negative (%dd): check date ordering", name, *val)})
			}
		}
	}
	return flags
}

func numStr(p *int) string {
	if p == nil {
		return "-"
	}
	return strconv.Itoa(*p)
}

func renderMetrics(advs []*Advisory, today dayOrdinal) string {
	var b strings.Builder
	b.WriteString("ID  SEV  TTP  DISC_GAP  REPLAT  EXPOSURE  XBP\n")
	var ttp, gap, rep, exp []int
	xbp, unp := 0, 0
	for _, a := range advs {
		w := advisoryWindows(a, today)
		exposure := numStr(w.ExposureWindow)
		if w.ExposureOpen && w.ExposureWindow != nil {
			exposure += "*"
		}
		sev := w.Severity
		if sev == "" {
			sev = "-"
		}
		xbpStr := "no"
		if w.ExploitedBeforePatch {
			xbpStr = "yes"
		}
		fmt.Fprintf(&b, "%s  %s  %s  %s  %s  %s  %s\n",
			w.ID, sev, numStr(w.TimeToPatch), numStr(w.DisclosureGap),
			numStr(w.ReportLatency), exposure, xbpStr)
		if w.TimeToPatch != nil {
			ttp = append(ttp, *w.TimeToPatch)
		}
		if w.DisclosureGap != nil {
			gap = append(gap, *w.DisclosureGap)
		}
		if w.ReportLatency != nil {
			rep = append(rep, *w.ReportLatency)
		}
		if w.ExposureWindow != nil {
			exp = append(exp, *w.ExposureWindow)
		}
		if w.ExploitedBeforePatch {
			xbp++
		}
		if w.Unpatched {
			unp++
		}
	}
	medStr := func(p *float64) string {
		if p == nil {
			return "-"
		}
		if *p == float64(int(*p)) {
			return strconv.Itoa(int(*p))
		}
		return strconv.FormatFloat(*p, 'f', -1, 64)
	}
	b.WriteString("\nAggregate (days; median):\n")
	fmt.Fprintf(&b, "  count                  %d\n", len(advs))
	fmt.Fprintf(&b, "  median time-to-patch   %s\n", medStr(median(ttp)))
	fmt.Fprintf(&b, "  median disclosure gap  %s\n", medStr(median(gap)))
	fmt.Fprintf(&b, "  median report latency  %s\n", medStr(median(rep)))
	fmt.Fprintf(&b, "  median exposure window %s\n", medStr(median(exp)))
	fmt.Fprintf(&b, "  exploited-before-patch %d\n", xbp)
	fmt.Fprintf(&b, "  unpatched              %d\n", unp)
	return b.String()
}

func renderFlags(flags []Flag) string {
	if len(flags) == 0 {
		return "No flags detected.\n"
	}
	var b strings.Builder
	b.WriteString("ID  KIND  SEVERITY  DETAIL\n")
	for _, f := range flags {
		fmt.Fprintf(&b, "%s  %s  %s  %s\n", f.ID, f.Kind, f.Severity, f.Detail)
	}
	fmt.Fprintf(&b, "\n%d flag(s) detected.\n", len(flags))
	return b.String()
}

func run(argv []string, stdout, stderr io.Writer) int {
	if len(argv) < 2 {
		fmt.Fprintln(stderr, "usage: vulntimeline <metrics|flags> <advisories.json> [--json] [--max-ttp N] [--fail-on-any]")
		return 1
	}
	cmd := argv[0]
	var path string
	asJSON, failOnAny := false, false
	var maxTTP *int
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--json":
			asJSON = true
		case a == "--fail-on-any":
			failOnAny = true
		case a == "--max-ttp":
			i++
			if i < len(argv) {
				v := atoi(argv[i])
				maxTTP = &v
			}
		case !strings.HasPrefix(a, "--"):
			path = a
		default:
			fmt.Fprintf(stderr, "error: unknown option %s\n", a)
			return 1
		}
	}
	if path == "" {
		fmt.Fprintln(stderr, "error: missing advisories path")
		return 1
	}
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	advs, err := loadAdvisories(data)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	today := toOrdinal(time.Now().UTC())

	switch cmd {
	case "metrics":
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			rows := []map[string]interface{}{}
			for _, a := range advs {
				w := advisoryWindows(a, today)
				rows = append(rows, map[string]interface{}{
					"id": w.ID, "severity": w.Severity,
					"time_to_patch": w.TimeToPatch, "disclosure_gap": w.DisclosureGap,
					"report_latency": w.ReportLatency, "exposure_window": w.ExposureWindow,
					"exposure_open": w.ExposureOpen, "exploited_before_patch": w.ExploitedBeforePatch,
					"unpatched": w.Unpatched,
				})
			}
			_ = enc.Encode(rows)
		} else {
			fmt.Fprint(stdout, renderMetrics(advs, today))
		}
		return 0
	case "flags":
		flags := detectFlags(advs, maxTTP, today)
		if asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(flags)
		} else {
			fmt.Fprint(stdout, renderFlags(flags))
		}
		if failOnAny && len(flags) > 0 {
			return 2
		}
		return 0
	default:
		fmt.Fprintf(stderr, "error: unknown command %s\n", cmd)
		return 1
	}
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
