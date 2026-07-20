//go:build !noentrypoint
// +build !noentrypoint

package cve

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config holds ingestion settings.
type Config struct {
	BatchSize    int           `json:"batch_size"`
	RetryDelay   time.Duration `json:"retry_delay"`
	Timeout       time.Duration `json:"timeout"`
	MaxRetries    int           `json:"max_retries"`
	ParallelJobs  int           `json:"parallel_jobs"`
	StrictMode    bool          `json:"strict_mode"`
	LogLevel      string        `json:"log_level"`
	TempDir       string        `json:"temp_dir"`
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:    100,
		RetryDelay:   time.Second * 5,
		Timeout:      time.Minute,
		MaxRetries:   3,
		ParallelJobs: 4,
		StrictMode:   true,
		LogLevel:     "info",
		TempDir:      "/tmp/vulntimeline",
	}
}

// CVE represents a normalized vulnerability record.
type CVE struct {
	ID              string          `json:"id"`
	PublishedDate   time.Time       `json:"published_date"`
	UpdatedDate     time.Time       `json:"updated_date"`
	CVSSv3Score     float64         `json:"cvss_v3_score"`
	CVSSv2Score     float64         `json:"cvss_v2_score"`
	Summary         string          `json:"summary"`
	Description     string          `json:"description"`
	AffectedSystems []AffectedEntry `json:"affected_systems"`
	References      []Reference     `json:"references"`
	Publishers      []Publisher     `json:"publishers"`
	CVSSv3Vector    string          `json:"cvss_v3_vector"`
	CVSSv2Vector    string          `json:"cvss_v2_vector"`
}

// AffectedEntry describes a specific affected system.
type AffectedEntry struct {
	Product       string   `json:"product"`
	VersionRange  string   `json:"version_range"`
	Severity      string   `json:"severity"`
	CVSSv3Score   float64  `json:"cvss_v3_score,omitempty"`
	CVSSv2Score   float64  `json:"cvss_v2_score,omitempty"`
	PublishedDate time.Time `json:"published_date"`
}

// Reference holds a URL or identifier reference.
type Reference struct {
	URL       string    `json:"url"`
	Type      string    `json:"type"` // e.g., "advisory", "patch"
	Source    string    `json:"source"`
	Published time.Time `json:"published_date,omitempty"`
}

// Publisher identifies the organization that published the CVE.
type Publisher struct {
	Name       string    `json:"name"`
	URL        string    `json:"url"`
	Category   string    `json:"category"` // e.g., "CISA", "NVD"
	ContactURL string    `json:"contact_url,omitempty"`
}

// SourceResult tracks ingestion results per source.
type SourceResult struct {
	Name         string
	Count        int
	Errors       []error
	Duplicates   int
	Skipped      int
	LastModified time.Time
}

// IngestionResult aggregates all results.
type IngestionResult struct {
	TotalProcessed int
	TotalValid     int
	TotalInvalid   int
	TotalDuplicates int
	Results        map[string]*SourceResult
	Errors         []error
	StartTime      time.Time
	EndTime        time.Time
}

// NVDJSON represents the NVD JSON structure.
type NVDJSON struct {
	Metadata struct {
		Timestamp    string `json:"timestamp"`
		Version      string `json:"version"`
		UpdatedDate  string `json:"updated_date"`
		PublishedDate string `json:"published_date"`
	} `json:"metadata"`
	CVEItems []struct {
		ID              string     `json:"cve_id"`
		State           string     `json:"state"`
		PublishedDate   string     `json:"published_date"`
		UpdatedDate     string     `json:"updated_date"`
		VendorIDs       []string   `json:"vendor_ids"`
		Desc            struct {
			Value    string `json:"value"`
			Language string `json:"lang,omitempty"`
		} `json:"desc"`
		Summary         string     `json:"summary"`
		CvssData        []struct {
			Version   string  `json:"version"`
			VectorStr string  `json:"vectorString"`
			Score     float64 `json:"score,omitempty"`
		} `json:"cvss_data"`
		AffectedProducts []struct {
			Vendor    string `json:"vendor"`
			Product   string `json:"product"`
			Version   string `json:"version"`
			CvssData  []struct {
				Version   string  `json:"version"`
				VectorStr string  `json:"vectorString"`
				Score     float64 `json:"score,omitempty"`
			} `json:"cvss_data"`
		} `json:"affected_products"`
		References []struct {
			URL       string `json:"url"`
			Type      string `json:"ref_source"`
			Description struct {
				Value    string `json:"value"`
				Language string `json:"lang,omitempty"`
			} `json:"desc"`
		} `json:"references"`
		Publishers []struct {
			Name       string `json:"name"`
			URL        string `json:"url"`
			Category   string `json:"category"`
			ContactURL string `json:"contact_url,omitempty"`
		} `json:"publishers"`
	} `json:"cve_items"`
}

// CISAXML represents a simplified CISA XML structure.
type CISAXML struct {
	XMLName    string `xml:"CISACVE"`
	Metadata   struct {
		Timestamp    string `xml:"timestamp"`
		Version      string `xml:"version"`
		UpdatedDate  string `xml:"updated_date"`
		PublishedDate string `xml:"published_date"`
	} `xml:"metadata"`
	CVEItems []struct {
		ID              string     `xml:"cve_id"`
		State           string     `xml:"state"`
		PublishedDate   string     `xml:"published_date"`
		UpdatedDate     string     `xml:"updated_date"`
		VendorIDs       []string   `xml:"vendor_ids"`
		Desc            struct {
			Value    string `xml:",chardata"`
			Language string `xml:"lang,omitempty"`
		} `xml:"desc"`
		Summary         string     `xml:"summary"`
		CvssData        []struct {
			Version   string  `xml:"version"`
			VectorStr string  `xml:"vectorString"`
			Score      float64 `xml:"score,omitempty"`
		} `xml:"cvss_data"`
		AffectedProducts []struct {
			Vendor    string `xml:"vendor"`
			Product   string `xml:"product"`
			Version   string `xml:"version"`
			CvssData  []struct {
				Version   string  `xml:"version"`
				VectorStr string  `xml:"vectorString"`
				Score      float64 `xml:"score,omitempty"`
			} `xml:"cvss_data"`
		} `xml:"affected_products"`
		References []struct {
			URL       string `xml:"url"`
			Type      string `xml:"ref_source"`
			Description struct {
				Value    string `xml:",chardata"`
				Language string `xml:"lang,omitempty"`
			} `xml:"desc"`
		} `xml:"references"`
		Publishers []struct {
			Name       string `xml:"name"`
			URL        string `xml:"url"`
			Category   string `xml:"category"`
			ContactURL string `xml:"contact_url,omitempty"`
		} `xml:"publishers"`
	} `xml:"cve_items"`
}

// CVEParser handles parsing from multiple sources.
type CVEParser struct {
	config    Config
	cache     map[string]*CVE
	cacheMu   sync.RWMutex
	tempDir   string
	httpClient *http.Client
}

// NewCVEParser creates a new parser with optional config override.
func NewCVEParser(cfg ...Config) *CVEParser {
	if len(cfg) == 0 || cfg[0].BatchSize <= 0 {
		cfg = append(cfg, DefaultConfig())
	}
	return &CVEParser{
		config:    cfg[0],
		cache:     make(map[string]*CVE),
		tempDir:   cfg[0].TempDir,
		httpClient: &http.Client{Timeout: cfg[0].Timeout},
	}
}

// ParseNVDJSON parses NVD JSON format. Returns parsed CVEs and errors.
func (p *CVEParser) ParseNVDJSON(data []byte) ([]*CVE, error) {
	var nvd NVDJSON
	if err := json.Unmarshal(data, &nvd); err != nil {
		return nil, fmt.Errorf("unmarshal NVD JSON: %w", err)
	}

	now, _ := time.Parse(time.RFC3339, nvd.Metadata.UpdatedDate)

	var results []*CVE
	for _, item := range nvd.CVEItems {
		if !isValidState(item.State) {
			continue
		}

		cve, err := p.parseNVDItem(&item, now)
		if err != nil {
			p.config.LogLevel = "debug"
			return results, fmt.Errorf("parse item %s: %w", item.ID, err)
		}

		results = append(results, cve)
	}

	return results, nil
}

// parseNVDItem parses a single NVD CVE item.
func (p *CVEParser) parseNVDItem(item *struct {
	ID              string     `json:"cve_id"`
	State           string     `json:"state"`
	PublishedDate   string     `json:"published_date"`
	UpdatedDate     string     `json:"updated_date"`
	VendorIDs       []string   `json:"vendor_ids"`
	Desc            struct {
		Value    string `json:"value"`
		Language string `json:"lang,omitempty"`
	} `json:"desc"`
	Summary         string     `json:"summary"`
	CvssData        []struct {
		Version   string  `json:"version"`
		VectorStr string  `json:"vectorString"`
		Score      float64 `json:"score,omitempty"`
	} `json:"cvss_data"`
	AffectedProducts []struct {
		Vendor    string `json:"vendor"`
		Product   string `json:"product"`
		Version   string `json:"version"`
		CvssData  []struct {
			Version   string  `json:"version"`
			VectorStr string  `json:"vectorString"`
			Score      float64 `json:"score,omitempty"`
		} `json:"cvss_data"`
	} `json:"affected_products"`
	References []struct {
		URL       string `json:"url"`
		Type      string `json:"ref_source"`
		Description struct {
			Value    string `json:"value"`
			Language string `json:"lang,omitempty"`
		} `json:"desc"`
	} `json:"references"`
	Publishers []struct {
		Name       string `json:"name"`
		URL        string `json:"url"`
		Category   string `json:"category"`
		ContactURL string `json:"contact_url,omitempty"`
	} `json:"publishers"`
}, now) (*CVE, error) {

	cve := &CVE{
		ID:              item.ID,
		PublishedDate:   p.parseDateTime(item.PublishedDate),
		UpdatedDate:     p.parseDateTime(item.UpdatedDate),
		Summary:         item.Summary,
	}

	if item.Desc.Value != "" {
		cve.Description = item.Desc.Value
	}

	// Extract CVSS v3 data
	for _, cvss := range item.CvssData {
		if cvss.Version == "3.0" || cvss.Version == "3.1" {
			cve.CVSSv3Score = cvss.Score
			cve.CVSSv3Vector = cvss.VectorStr
			break
		}
	}

	// Extract CVSS v2 data
	for _, cvss := range item.CvssData {
		if cvss.Version == "2.0" || cvss.Version == "2.1" {
			cve.CVSSv2Score = cvss.Score
			cve.CVSSv2Vector = cvss.VectorStr
			break
		}
	}

	// Parse affected products and systems
	for _, prod := range item.AffectedProducts {
		if prod.Product == "" || prod.Version == "" {
			continue
		}

		entry := AffectedEntry{
			Product:       prod.Product,
			VersionRange:  prod.Version,
			PublishedDate: now,
		}

		for _, cvss := range prod.CvssData {
			if cvss.Version == "3.0" || cvss.Version == "3.1" {
				entry.CVSSv3Score = cvss.Score
				break
			} else if cvss.Version == "2.0" || cvss.Version == "2.1" {
				entry.CVSSv2Score = cvss.Score
				break
			}
		}

		cve.AffectedSystems = append(cve.AffectedSystems, entry)
	}

	// Parse references
	for _, ref := range item.References {
		if ref.URL == "" {
			continue
		}

		refEntry := Reference{
			URL:  ref.URL,
			Type: strings.ToLower(ref.Type),
		}

		if ref.Description.Value != "" {
			refEntry.Description = ref.Description.Value
		}

		cve.References = append(cve.References, refEntry)
	}

	// Parse publishers
	for _, pub := range item.Publishers {
		if pub.Name == "" || pub.URL == "" {
			continue
		}

		pubEntry := Publisher{
			Name:       pub.Name,
			URL:        pub.URL,
			Category:   strings.ToLower(pub.Category),
			ContactURL: pub.ContactURL,
		}

		cve.Publishers = append(cve.Publishers, pubEntry)
	}

	return cve, nil
}

// ParseCISAXML parses CISA XML format. Returns parsed CVEs and errors.
func (p *CVEParser) ParseCISAXML(data []byte) ([]*CVE, error) {
	var cisax CISAXML
	if err := json.Unmarshal(data, &cisax); err != nil {
		return nil, fmt.Errorf("unmarshal CISA XML: %w", err)
	}

	now, _ := time.Parse(time.RFC3339, cisax.Metadata.UpdatedDate)

	var results []*CVE
	for _, item := range cisax.CVEItems {
		if !isValidState(item.State) {
			continue
		}

		cve, err := p.parseCISAItem(&item, now)
		if err != nil {
			p.config.LogLevel = "debug"
			return results, fmt.Errorf("parse item %s: %w", item.ID, err)
		}

		results = append(results, cve)
	}

	return results, nil
}

// parseCISAItem parses a single CISA CVE item.
func (p *CVEParser) parseCISAItem(item *struct {
	ID              string     `xml:"cve_id"`
	State           string     `xml:"state"`
	PublishedDate   string     `xml:"published_date"`
	UpdatedDate     string     `xml:"updated_date"`
	VendorIDs       []string   `xml:"vendor_ids"`
	Desc