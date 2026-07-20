package timeline_builder

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Severity represents the severity level of a vulnerability
type Severity string

const (
	SecHigh   Severity = "HIGH"
	SecMedium Severity = "MEDIUM"
	SecLow    Severity = "LOW"
	SecInfo   Severity = "INFO"
)

// VulnerabilityEvent holds a single vulnerability timeline event
type VulnerabilityEvent struct {
	CVEID       string `json:"cve_id,omitempty"`
	Component   string `json:"component"`
	Version     string `json:"version"`
	DiscoveryAt time.Time `json:"discovery_at"`
	ReportedAt  time.Time `json:"reported_at"`
	FixedAt     *time.Time `json:"fixed_at,omitempty"`
	Severity    Severity  `json:"severity"`
	Description string `json:"description,omitempty"`
}

// TimelineResult holds the complete timeline output
type TimelineResult struct {
	Events      []VulnerabilityEvent
	TotalDays   int
	AvgPatchWindow float64
	MaxPatchWindow int
	MinPatchWindow int
	Summary     map[Severity]int
}

// Config holds optional configuration for building timelines
type Config struct {
	Timezone    string // Default: "UTC"
	IncludeNull bool   // Include events with missing dates
}

// EventSource represents where the raw data comes from
type EventSource interface {
	Read() ([]VulnerabilityEvent, error)
}

// JSONSource reads vulnerability events from a JSON file or stream
type JSONSource struct {
	Path string
	Reader io.Reader
}

func (j *JSONSource) Read() ([]VulnerabilityEvent, error) {
	var events []VulnerabilityEvent
	
	if j.Path != "" {
		data, err := os.ReadFile(j.Path)
		if err != nil {
			return nil, fmt.Errorf("reading file: %w", err)
		}
		err = json.Unmarshal(data, &events)
	} else if j.Reader != nil {
		var data []byte
		data, err := io.ReadAll(j.Reader)
		if err != nil {
			return nil, fmt.Errorf("reading stream: %w", err)
		}
		err = json.Unmarshal(data, &events)
	} else {
		return events, nil
	}

	if len(events) == 0 {
		return events, nil
	}

	// Normalize all timestamps to UTC
	for i := range events {
		events[i].DiscoveryAt = events[i].DiscoveryAt.UTC()
		events[i].ReportedAt = events[i].ReportedAt.UTC()
		if events[i].FixedAt != nil {
			events[i].FixedAt = (*events[i].FixedAt).UTC()
		}
	}

	return events, nil
}

// FileSource reads from a file path directly
type FileSource struct {
	Path string
}

func (f *FileSource) Read() ([]VulnerabilityEvent, error) {
	data, err := os.ReadFile(f.Path)
	if err != nil {
		return nil, fmt.Errorf("reading file %q: %w", f.Path, err)
	}
	
	var events []VulnerabilityEvent
	err = json.Unmarshal(data, &events)
	if err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}

	for i := range events {
		events[i].DiscoveryAt = events[i].DiscoveryAt.UTC()
		events[i].ReportedAt = events[i].ReportedAt.UTC()
		if events[i].FixedAt != nil {
			events[i].FixedAt = (*events[i].FixedAt).UTC()
		}
	}

	return events, nil
}

// BuildTimeline creates a sorted timeline from raw events
func BuildTimeline(events []VulnerabilityEvent, cfg Config) (TimelineResult, error) {
	if len(events) == 0 {
		return TimelineResult{}, nil
	}

	// Sort by discovery date first, then reported, then fixed
	sort.SliceStable(events, func(i, j int) bool {
		if !events[i].DiscoveryAt.Equal(events[j].DiscoveryAt) {
			return events[i].DiscoveryAt.Before(events[j].DiscoveryAt)
		}
		if !events[i].ReportedAt.Equal(events[j].ReportedAt) {
			return events[i].ReportedAt.Before(events[j].ReportedAt)
		}
		if events[i].FixedAt == nil || events[j].FixedAt == nil {
			return events[i].FixedAt != nil
		}
		return *events[i].FixedAt.Before(*events[j].FixedAt)
	})

	result := TimelineResult{
		Events: events,
		Summary: make(map[Severity]int),
	}

	now := time.Now()
	if cfg.Timezone != "" {
		loc, err := time.LoadLocation(cfg.Timezone)
		if err == nil {
			now = now.In(loc)
		} else {
			now = now.UTC()
		}
	}

	totalDays := 0
	var patchWindows []int64
	minWindow := int64(365 * 24 * 7) // Default to 1 week
	maxWindow := int64(-1)

	for _, e := range events {
		result.Summary[e.Severity]++

		if !e.DiscoveryAt.IsZero() && !e.ReportedAt.IsZero() {
			days := e.ReportedAt.Sub(e.DiscoveryAt).Hours() / 24.0
			totalDays += int(days)
		}

		if e.FixedAt != nil && !e.DiscoveryAt.IsZero() {
			window := e.FixedAt.Sub(e.DiscoveryAt).Hours() / 24.0
			patchWindows = append(patchWindows, int64(window))
			
			if window < minWindow {
				minWindow = int64(window)
			}
			if window > maxWindow {
				maxWindow = int64(window)
			}
		}

		// Calculate total span from first discovery to now or last fixed
		start := e.DiscoveryAt
		end := now
		if !e.FixedAt.IsZero() && end.Before(*e.FixedAt) {
			end = *e.FixedAt
		}
		
		totalDays += int(end.Sub(start).Hours()) / 24.0
	}

	result.TotalDays = totalDays
	
	var sum float64
	count := 0
	for _, w := range patchWindows {
		sum += float64(w)
		count++
	}
	
	if count > 0 {
		result.AvgPatchWindow = sum / float64(count)
		result.MaxPatchWindow = int(maxWindow)
		result.MinPatchWindow = int(minWindow)
	}

	return result, nil
}

// FormatEvent creates a human-readable string for a single event
func FormatEvent(e VulnerabilityEvent) string {
	var parts []string
	
	if !e.DiscoveryAt.IsZero() {
		parts = append(parts, fmt.Sprintf("Discovered: %s", e.DiscoveryAt.Format("2006-01-02 15:04"))[:19])
	}
	
	if !e.ReportedAt.IsZero() {
		parts = append(parts, fmt.Sprintf("Reported:   %s", e.ReportedAt.Format("2006-01-02 15:04"))[:19])
	}
	
	if e.FixedAt != nil && !e.FixedAt.IsZero() {
		parts = append(parts, fmt.Sprintf("Fixed:      %s", (*e.FixedAt).Format("2006-01-02 15:04"))[:19])
	} else if e.Severity != SecInfo {
		parts = append(parts, "Pending fix")
	}

	if len(parts) == 0 {
		return fmt.Sprintf("%s [%s] %s", e.Component, e.Severity, e.Description)
	}

	return strings.Join(parts, ", ") + " | " + e.Component + " v" + e.Version + " (" + string(e.Severity) + ")"
}

// FormatTimelineResult creates a formatted output for the complete timeline
func FormatTimelineResult(result TimelineResult) string {
	var sb strings.Builder
	
	sb.WriteString("=== VULN TIMELINE SUMMARY ===\n\n")
	
	if len(result.Events) == 0 {
		sb.WriteString("No events found.\n")
		return sb.String()
	}

	sb.WriteString(fmt.Sprintf("Total Events:    %d\n", len(result.Events)))
	sb.WriteString(fmt.Sprintf("Time Span:      %.1f days\n", float64(result.TotalDays)/24.0))

	if result.AvgPatchWindow > 0 {
		sb.WriteString(fmt.Sprintf("Avg Patch Window: %.2f days\n", result.AvgPatchWindow))
		sb.WriteString(fmt.Sprintf("Min Patch Window: %d days\n", result.MinPatchWindow))
		sb.WriteString(fmt.Sprintf("Max Patch Window: %d days\n", result.MaxPatchWindow))
	}

	sb.WriteString("\n--- BY SEVERITY ---\n")
	for sev, count := range []Severity{SecHigh, SecMedium, SecLow, SecInfo} {
		if result.Summary[sev] > 0 {
			sb.WriteString(fmt.Sprintf("  %s: %d\n", sev, result.Summary[sev]))
		}
	}

	sb.WriteString("\n--- DETAILED TIMELINE ---\n")
	
	for _, e := range result.Events {
		sb.WriteString(fmt.Sprintf("%-12s %-8s ", 
			e.Component[:min(30, len(e.Component))],
			string(e.Severity)))
		
		if !e.DiscoveryAt.IsZero() && !e.ReportedAt.IsZero() {
			days := e.ReportedAt.Sub(e.DiscoveryAt).Hours() / 24.0
			sb.WriteString(fmt.Sprintf("Rpt: %.1fd", days))
		} else if !e.DiscoveryAt.IsZero() {
			sb.WriteString("Discovered")
		}
		
		if e.FixedAt != nil && !e.FixedAt.IsZero() {
			days := (*e.FixedAt).Sub(e.DiscoveryAt).Hours() / 24.0
			sb.WriteString(fmt.Sprintf(" Fix: %.1fd", days))
		} else if e.Severity == SecInfo {
			sb.WriteString(" Pending")
		}
		
		sb.WriteString("\n")
	}

	return sb.String()
}

// SourceFromPath creates a JSONSource from a file path string
func SourceFromPath(path string) EventSource {
	return &FileSource{Path: path}
}

// BuildAndFormat is the main convenience function for quick usage
func BuildAndFormat(events []VulnerabilityEvent, cfg Config) (string, error) {
	result, err := BuildTimeline(events, cfg)
	if err != nil {
		return "", fmt.Errorf("building timeline: %w", err)
	}
	
	return FormatTimelineResult(result), nil
}

// Demo function for testing and demonstration purposes
func RunDemo() {
	// Sample vulnerability data
	sampleData := []VulnerabilityEvent{
		{
			CVEID:       "CVE-2024-1234",
			Component:   "libssl",
			Version:     "3.2.1",
			DiscoveryAt: time.Date(2024, 1, 15, 10, 0, 0, 0, time.UTC),
			ReportedAt:  time.Date(2024, 1, 28, 14, 30, 0, 0, time.UTC),
			FixedAt:     &time.Time{}, // Will be set below
			Severity:    SecHigh,
			Description: "Buffer overflow in TLS handshake",
		},
		{
			CVEID:       "CVE-2024-5678",
			Component:   "nginx",
			Version:     "1.25.3",
			DiscoveryAt: time.Date(2024, 2, 1, 9, 0, 0, 0, time.UTC),
			ReportedAt:  time.Date(2024, 2, 15, 16, 0, 0, 0, time.UTC),
			FixedAt:     &time.Time{}, // Will be set below
			Severity:    SecMedium,
			Description: "HTTP/2 header injection",
		},
		{
			CVEID:       "CVE-2024-9999",
			Component:   "redis-server",
			Version:     "7.2.0",
			DiscoveryAt: time.Date(2024, 3, 10, 8, 0, 0, 0, time.UTC),
			ReportedAt:  time.Date(2024, 3, 12, 10, 0, 0, 0, time.UTC),
			FixedAt:     &time.Time{}, // Will be set below
			Severity:    SecLow,
			Description: "Minor memory leak in replication",
		},
	}

	// Set fixed dates for demo
	now := time.Now()
	fixedDates := []time.Time{
		time.Date(2024, 1, 31, 12, 0, 0, 0, time.UTC), // libssl fixed in ~45 days
		time.Date(2024, 2, 28, 18, 0, 0, 0, time.UTC), // nginx fixed in ~43 days  
		now,                                          // redis still pending
	}

	for i := range sampleData {
		sampleData[i].FixedAt = &fixedDates[i]
	}

	fmt.Println("=== VULN TIMELINE BUILDER DEMO ===\n")
	
	result, err := BuildTimeline(sampleData, Config{Timezone: "UTC"})
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	output, _ := FormatTimelineResult(result)
	fmt.Println(output)
	
	// Calculate and display key metrics
	fmt.Println("\n=== KEY METRICS ===")
	fmt.Printf("  Average Patch Window: %.2f days\n", result.AvgPatchWindow)
	fmt.Printf("  Min Patch Window: %d days\n", result.MinPatchWindow)
	fmt.Printf("  Max Patch Window: %d days\n", result.MaxPatchWindow)
}

func main() {
	// Run the demo when executed directly
	RunDemo()
	
	// Example usage with file input
	if len(os.Args) > 1 {
		cfg := Config{Timezone: "UTC"}
		
		source := SourceFromPath(os.Args[1])
		events, err := source.Read()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading events: %v\n", err)
			os.Exit(1)
		}

		result, err := BuildTimeline(events, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error building timeline: %v\n", err)
			os.Exit(1)
		}

		output, _ := FormatTimelineResult(result)
		fmt.Println(output)
		
		// Output JSON summary to stdout for piping
		jsonSummary, _ := json.MarshalIndent(map[string]interface{}{
			"total_events": len(result.Events),
			"time_span_days": result.TotalDays,
			"avg_patch_window": result.AvgPatchWindow,
			"severity_summary": result.Summary,
		}, "", "  ")
		fmt.Printf("\n=== JSON SUMMARY ===\n%s\n", string(jsonSummary))
	}
}