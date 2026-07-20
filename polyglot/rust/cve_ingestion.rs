use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fmt;

/// CVE record structure for ingestion pipeline
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveRecord {
    pub id: String,
    pub summary: String,
    #[serde(default)]
    pub affected_products: Vec<AffectedProduct>,
    #[serde(default)]
    pub cvss_v3_score: Option<f64>,
    #[serde(default)]
    pub published_date: DateTime<Utc>,
    #[serde(default)]
    pub last_modified_date: DateTime<Utc>,
    #[serde(default)]
    pub patch_notes: String,
}

/// Affected product with version ranges
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AffectedProduct {
    pub name: String,
    #[serde(default)]
    pub versions: Vec<VersionRange>,
}

/// Version range specification (supports semver-like syntax)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VersionRange {
    /// Exact version match
    Exact(String),
    /// Range like ">=1.0.0 <2.0.0"
    Range(String),
}

/// Ingestion result with metrics and validation state
#[derive(Debug, Default)]
pub struct IngestionResult {
    pub records: Vec<CveRecord>,
    pub warnings: Vec<IngestionWarning>,
    pub errors: Vec<IngestionError>,
    pub metrics: Metrics,
}

/// Warning types for non-fatal issues during ingestion
#[derive(Debug, Clone)]
pub enum IngestionWarning {
    DuplicateId(String),
    MissingRequiredField(String),
    InvalidDateFormat(String),
    UnknownSeverityLevel(String),
    EmptyAffectedProducts,
}

/// Error types for fatal issues during ingestion
#[derive(Debug, Clone)]
pub enum IngestionError {
    ParseError(String),
    ValidationError(String),
    IoError(std::io::Error),
    TypeConversionError(String),
}

impl fmt::Display for IngestionWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestionWarning::DuplicateId(id) => write!(f, "Duplicate CVE ID detected: {}", id),
            IngestionWarning::MissingRequiredField(field) => {
                write!(f, "Missing required field in record: {}", field)
            }
            IngestionWarning::InvalidDateFormat(date) => {
                write!(f, "Invalid date format encountered: {}", date)
            }
            IngestionWarning::UnknownSeverityLevel(level) => {
                write!(f, "Unknown severity level: {}", level)
            }
            IngestionWarning::EmptyAffectedProducts => {
                write!(f, "CVE record has no affected products specified")
            }
        }
    }
}

impl fmt::Display for IngestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestionError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            IngestionError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            IngestionError::IoError(e) => write!(f, "IO error: {}", e),
            IngestionError::TypeConversionError(msg) => {
                write!(f, "Type conversion error: {}", msg)
            }
        }
    }
}

/// Metrics collected during ingestion batch
#[derive(Debug, Default)]
pub struct Metrics {
    pub total_records: usize,
    pub valid_records: usize,
    pub duplicate_ids_found: usize,
    pub missing_fields_count: usize,
    pub average_patch_window_days: f64,
}

impl CveRecord {
    /// Calculate patch window from publication to first known patch date
    pub fn calculate_patch_window(&self) -> Option<Duration> {
        let published = self.published_date;
        
        // Extract approximate patch date from notes or use last_modified as proxy
        let patch_proxy = self.last_modified_date.max(published);
        
        if patch_proxy > published {
            Some(patch_proxy - published)
        } else {
            None
        }
    }

    /// Check if record has minimal required data
    pub fn is_minimally_valid(&self) -> bool {
        !self.id.is_empty() && 
        !self.summary.is_empty() && 
        !self.affected_products.is_empty()
    }

    /// Generate a hash for duplicate detection
    pub fn id_hash(&self) -> u64 {
        self.id.as_bytes().iter()
            .fold(0u64, |acc, &b| acc.wrapping_add(b as u64))
    }
}

impl IngestionResult {
    /// Calculate average patch window across all records
    pub fn calculate_average_patch_window(&self) -> f64 {
        let windows: Vec<_> = self.records.iter()
            .filter_map(|r| r.calculate_patch_window())
            .collect();
        
        if windows.is_empty() {
            return 0.0;
        }

        let total_days: f64 = windows.iter()
            .map(|d| d.num_days() as f64)
            .sum();
        
        (total_days / windows.len() as f64).round() * 10.0 / 10.0 // Round to 1 decimal
    }

    /// Check for duplicate CVE IDs and deduplicate
    pub fn deduplicate(&mut self, keep_first: bool) {
        let mut seen_ids: HashSet<u64> = HashSet::new();
        let mut duplicates_found = 0;
        
        // Collect indices of duplicates
        let mut dup_indices: Vec<usize> = Vec::new();
        
        for (i, record) in self.records.iter().enumerate() {
            if !record.id.is_empty() {
                let hash = record.id_hash();
                
                if seen_ids.contains(&hash) {
                    duplicates_found += 1;
                    dup_indices.push(i);
                } else {
                    seen_ids.insert(hash);
                }
            }
        }

        // Add warnings for duplicates found
        for idx in &dup_indices {
            self.warnings.push(IngestionWarning::DuplicateId(
                &self.records[*idx].id,
            ));
        }

        // Remove duplicates (keep first by default)
        if !dup_indices.is_empty() && keep_first {
            dup_indices.sort();
            for idx in dup_indices.iter().rev() {
                self.records.remove(*idx);
            }
        }
    }

    /// Validate all records and collect warnings/errors
    pub fn validate_all(&mut self) -> &mut Self {
        let mut missing_fields = 0;
        
        for record in &mut self.records {
            // Check required fields
            if record.id.is_empty() {
                missing_fields += 1;
                continue;
            }

            if !record.summary.is_empty() && !record.affected_products.is_empty() {
                // Record is minimally valid
                continue;
            }

            if record.affected_products.is_empty() {
                self.warnings.push(IngestionWarning::EmptyAffectedProducts);
            }

            // Validate dates
            if let Some(ts) = &record.published_date {
                if ts.year() < 2000 || ts.year() > Utc::now().year() + 5 {
                    self.warnings.push(IngestionWarning::InvalidDateFormat(
                        format!("{} (out of expected range)", record.id),
                    ));
                }
            }

            // Validate CVSS score if present
            if let Some(score) = &record.cvss_v3_score {
                if *score < 0.0 || *score > 10.0 {
                    self.warnings.push(IngestionWarning::UnknownSeverityLevel(
                        format!("{}: invalid CVSS score {}", record.id, score),
                    ));
                }
            }

            // Check for missing required fields
            if !record.summary.is_empty() && !record.affected_products.is_empty() {
                continue;
            }
            
            missing_fields += 1;
        }

        self.metrics.missing_fields_count = missing_fields;
        self
    }
}

/// Main ingestion function - orchestrates the full pipeline
pub fn ingest_cves(input: &str) -> IngestionResult {
    let mut result = IngestionResult::default();
    
    // Parse JSON input
    let records: Vec<CveRecord> = match serde_json::from_str(input) {
        Ok(parsed) => parsed,
        Err(e) => {
            result.errors.push(IngestionError::ParseError(format!(
                "Failed to parse input JSON: {}", e
            )));
            return result;
        }
    };

    result.metrics.total_records = records.len();

    // Validate all records
    result.validate_all();

    // Deduplicate (keeps first occurrence)
    result.deduplicate(true);

    // Calculate metrics
    result.metrics.valid_records = result.records.len();
    result.metrics.average_patch_window_days = 
        result.calculate_average_patch_window();

    // Sort warnings by severity (duplicates last, missing fields first)
    result.warnings.sort_by(|a, b| {
        let priority_a = match a {
            IngestionWarning::MissingRequiredField(_) => 0,
            IngestionWarning::InvalidDateFormat(_) => 1,
            IngestionWarning::UnknownSeverityLevel(_) => 2,
            IngestionWarning::EmptyAffectedProducts => 3,
            IngestionWarning::DuplicateId(_) => 4,
        };
        let priority_b = match b {
            IngestionWarning::MissingRequiredField(_) => 0,
            IngestionWarning::InvalidDateFormat(_) => 1,
            IngestionWarning::UnknownSeverityLevel(_) => 2,
            IngestionWarning::EmptyAffectedProducts => 3,
            IngestionWarning::DuplicateId(_) => 4,
        };
        priority_a.cmp(&priority_b)
    });

    result
}

/// Example input data for demonstration (matches real CVE JSON structure)
const SAMPLE_INPUT: &str = r#"
[
    {
        "id": "CVE-2024-1234",
        "summary": "Buffer overflow in example library before 2.5.0",
        "affected_products": [
            {
                "name": "example-lib",
                "versions": ["<2.5.0"]
            }
        ],
        "cvss_v3_score": 7.8,
        "published_date": "2024-01-15T10:30:00Z",
        "last_modified_date": "2024-02-01T14:20:00Z",
        "patch_notes": "Fixed in 2.5.0 release"
    },
    {
        "id": "CVE-2024-1234",
        "summary": "Buffer overflow in example library before 2.5.0 (duplicate)",
        "affected_products": [
            {
                "name": "example-lib",
                "versions": ["<2.5.0"]
            }
        ],
        "cvss_v3_score": 7.8,
        "published_date": "2024-01-16T09:00:00Z",
        "last_modified_date": "2024-02-02T10:00:00Z"
    },
    {
        "id": "CVE-2024-5678",
        "summary": "Authentication bypass in web framework",
        "affected_products": [],
        "cvss_v3_score": 9.1,
        "published_date": "2024-03-01T08:00:00Z",
        "last_modified_date": "2024-03-05T16:00:00Z"
    },
    {
        "id": "",
        "summary": "Empty ID test case",
        "affected_products": [
            {
                "name": "test-lib",
                "versions": ["<1.0.0"]
            }
        ],
        "published_date": "2024-03-10T12:00:00Z"
    },
    {
        "id": "CVE-2024-9999",
        "summary": "Memory leak in network stack",
        "affected_products": [
            {
                "name": "net-stack",
                "versions": [">=1.0.0 <3.0.0"]
            }
        ],
        "cvss_v3_score": 4.5,
        "published_date": "2024-04-01T06:00:00Z",
        "last_modified_date": "2024-04-15T18:00:00Z",
        "patch_notes": "Fixed in 3.0.0 beta"
    }
]
"#;

fn main() {
    println!("=== VulnTimeline CVE Ingestion Demo ===\n");

    // Run ingestion with sample data
    let result = ingest_cves(SAMPLE_INPUT);

    // Print summary metrics
    println!("Ingestion Summary:");
    println!("  Total records processed: {}", result.metrics.total_records);
    println!("  Valid records after dedup: {}", result.metrics.valid_records);
    println!("  Duplicates found and removed: {}", 
        result.metrics.total_records - result.metrics.valid_records);
    println!("  Missing fields count: {}", result.metrics.missing_fields_count);
    println!("  Average patch window: {:.1} days", result.metrics.average_patch_window_days);

    // Print warnings
    if !result.warnings.is_empty() {
        println!("\nWarnings ({}):", result.warnings.len());
        for warning in &result.warnings {
            println!("  - {}", warning);
        }
    }

    // Print errors
    if !result.errors.is_empty() {
        println!("\nErrors ({}):", result.errors.len());
        for error in &result.errors {
            println!("  - {}", error);
        }
    }

    // Show deduplicated records
    println!("\n=== Deduplicated Records ===");
    for record in &result.records {
        let patch_window = match record.calculate_patch_window() {
            Some(window) => format!("Patch window: {:.1} days", window.num_days()),
            None => "Patch window: unknown".to_string(),
        };
        
        println!("\nCVE: {}", record.id);
        println!("  Summary: {}", record.summary);
        println!("  Products: {:?}", record.affected_products.iter()
            .map(|p| &p.name)
            .collect::<Vec<_>>());
        println!("  CVSS v3: {:?} | {}", 
            record.cvss_v3_score, patch_window);
    }

    // Demonstrate error handling with malformed input
    println!("\n=== Error Handling Demo ===");
    
    let malformed_input = r#"
[
    {
        "id": "CVE-2024-BAD",
        "summary": "Test",
        "affected_products": [],
        "published_date": "not-a-date"
    }
]
"#;

    let bad_result = ingest_cves(malformed_input);
    
    println!("Malformed input result:");
    println!("  Errors: {}", bad_result.errors.len());
    for e in &bad_result.errors {
        println!("    - {}", e);
    }

    // Demonstrate streaming ingestion (simulated)
    println!("\n=== Streaming Ingestion Demo ===");
    
    let batch_size = 100;
    let total_batches = 5;
    let mut running_total: usize = 0;
    
    for batch in 1..=total_batches {
        // Simulate processing a batch
        let batch_records = ingest_cves(SAMPLE_INPUT);
        
        println!("Batch {}: {} records processed, {} valid", 
            batch, 
            batch_records.metrics.total_records,
            batch_records.metrics.valid_records);
        
        running_total += batch_records.metrics.valid_records;
    }

    println!("\nTotal processed across batches: {}", running_total);

    // Demonstrate custom output formatting
    println!("\n=== Custom Output Formatting Demo ===");