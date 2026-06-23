package main

import (
	"bytes"
	"strings"
	"testing"
)

func mustParse(t *testing.T, s string) dayOrdinal {
	t.Helper()
	d, ok, err := parseDate(s)
	if err != nil || !ok {
		t.Fatalf("parseDate(%q) failed: ok=%v err=%v", s, ok, err)
	}
	return d
}

func TestParseDateFormats(t *testing.T) {
	iso := mustParse(t, "2025-02-10")
	if mustParse(t, "02/10/2025") != iso {
		t.Error("US date mismatch")
	}
	if mustParse(t, "2025/02/10") != iso {
		t.Error("slashed YMD mismatch")
	}
	if mustParse(t, "20250210") != iso {
		t.Error("compact mismatch")
	}
	if mustParse(t, "February 10, 2025") != iso {
		t.Error("spelled mismatch")
	}
	if mustParse(t, "2025-02-10T09:30:00Z") != iso {
		t.Error("datetime mismatch")
	}
}

func TestParseDateEmptyAndNil(t *testing.T) {
	if _, ok, _ := parseDate(nil); ok {
		t.Error("nil should be absent")
	}
	if _, ok, _ := parseDate(""); ok {
		t.Error("empty should be absent")
	}
	if _, _, err := parseDate("not-a-date"); err == nil {
		t.Error("garbage should error")
	}
}

func TestLoadRequiresID(t *testing.T) {
	if _, err := loadAdvisories([]byte(`[{"title":"x"}]`)); err == nil {
		t.Error("missing id should error")
	}
}

func TestLoadDuplicateID(t *testing.T) {
	if _, err := loadAdvisories([]byte(`[{"id":"A"},{"id":"A"}]`)); err == nil {
		t.Error("duplicate id should error")
	}
}

func TestWindowsTimeToPatch(t *testing.T) {
	advs, err := loadAdvisories([]byte(`[{"id":"X","disclosed":"2025-02-10","patched":"2025-02-12"}]`))
	if err != nil {
		t.Fatal(err)
	}
	w := advisoryWindows(advs[0], 0)
	if w.TimeToPatch == nil || *w.TimeToPatch != 2 {
		t.Errorf("time-to-patch want 2 got %v", w.TimeToPatch)
	}
	if w.Unpatched {
		t.Error("should be patched")
	}
}

func TestWindowsExploitedBeforePatch(t *testing.T) {
	advs, _ := loadAdvisories([]byte(`[{"id":"X","disclosed":"2025-02-10","exploited":"2025-02-11","patched":"2025-02-12"}]`))
	w := advisoryWindows(advs[0], 0)
	if !w.ExploitedBeforePatch {
		t.Error("expected exploited-before-patch")
	}
	if w.ExposureWindow == nil || *w.ExposureWindow != 1 {
		t.Errorf("exposure want 1 got %v", w.ExposureWindow)
	}
}

func TestWindowsUnpatchedExploitedOpen(t *testing.T) {
	advs, _ := loadAdvisories([]byte(`[{"id":"X","exploited":"2020-01-01"}]`))
	w := advisoryWindows(advs[0], mustParse(t, "2020-01-11"))
	if !w.Unpatched || !w.ExposureOpen {
		t.Error("expected unpatched + open exposure")
	}
	if w.ExposureWindow == nil || *w.ExposureWindow != 10 {
		t.Errorf("exposure want 10 got %v", w.ExposureWindow)
	}
}

func TestMedian(t *testing.T) {
	advs, _ := loadAdvisories([]byte(`[
		{"id":"A","disclosed":"2025-01-01","patched":"2025-01-05"},
		{"id":"B","disclosed":"2025-01-01","patched":"2025-01-11"}]`))
	out := renderMetrics(advs, 0)
	if !strings.Contains(out, "median time-to-patch   7") {
		t.Errorf("expected median 7, got:\n%s", out)
	}
}

func TestDetectFlags(t *testing.T) {
	advs, _ := loadAdvisories([]byte(`[{"id":"A","disclosed":"2025-01-01","exploited":"2025-01-02"}]`))
	flags := detectFlags(advs, nil, mustParse(t, "2025-02-01"))
	kinds := map[string]bool{}
	for _, f := range flags {
		kinds[f.Kind] = true
	}
	if !kinds["exploited_before_patch"] || !kinds["unpatched"] {
		t.Errorf("missing flags, got %v", kinds)
	}
}

func TestSlowPatchThreshold(t *testing.T) {
	advs, _ := loadAdvisories([]byte(`[{"id":"A","disclosed":"2025-01-01","patched":"2025-03-01"}]`))
	thirty := 30
	ninety := 90
	if n := len(filterKind(detectFlags(advs, &thirty, 0), "slow_patch")); n != 1 {
		t.Errorf("want 1 slow_patch at 30, got %d", n)
	}
	if n := len(filterKind(detectFlags(advs, &ninety, 0), "slow_patch")); n != 0 {
		t.Errorf("want 0 slow_patch at 90, got %d", n)
	}
}

func TestNegativeWindow(t *testing.T) {
	advs, _ := loadAdvisories([]byte(`[{"id":"A","disclosed":"2025-02-10","patched":"2025-02-01"}]`))
	if len(filterKind(detectFlags(advs, nil, 0), "negative_window")) == 0 {
		t.Error("expected negative_window flag")
	}
}

func TestRunFailOnAny(t *testing.T) {
	tmp := t.TempDir() + "/a.json"
	if err := writeFile(tmp, `{"advisories":[{"id":"A","disclosed":"2025-01-01","exploited":"2025-01-02"}]}`); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rc := run([]string{"flags", tmp, "--fail-on-any"}, &out, &errb)
	if rc != 2 {
		t.Errorf("want exit 2, got %d", rc)
	}
}

func filterKind(flags []Flag, kind string) []Flag {
	var out []Flag
	for _, f := range flags {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func writeFile(path, content string) error {
	return osWriteFile(path, content)
}
