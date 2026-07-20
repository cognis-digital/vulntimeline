using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace vulntimeline
{
    /// <summary>
    /// Configuration for CVE ingestion pipeline.
    /// </summary>
    public class IngestionConfig
    {
        public bool StrictValidation { get; set; } = true;
        public int MaxRecordsPerBatch { get; set; } = 10000;
        public TimeSpan? TimeoutPerRecord { get; set; }
        public string DefaultDiscoveryDateFormat { get; set; } = "yyyy-MM-dd";
    }

    /// <summary>
    /// Represents a single CVE record with all metadata.
    /// </summary>
    [System.Diagnostics.CodeAnalysis.SuppressMessage("Style", "IDE0053:Use nested type", Justification = "Top-level for tool scope")]
    public class CveRecord
    {
        public string Id { get; set; }
        public DateTime? DiscoveryDate { get; set; }
        public DateTime? PatchReleaseDate { get; set; }
        public string PackageName { get; set; }
        public string VersionRange { get; set; }
        public string Description { get; set; }
        public string CvssScore { get; set; }
        public string Severity { get; set; }
        public List<string> Sources { get; set; } = new();
        public Dictionary<string, object> Metadata { get; set; } = new();

        /// <summary>
        /// Calculated metrics after ingestion.
        /// </summary>
        public PatchWindowMetrics Metrics { get; set; } = null!;

        public bool IsValid => !string.IsNullOrEmpty(Id);
    }

    /// <summary>
    /// Calculated patch window metrics for a CVE record.
    /// </summary>
    public class PatchWindowMetrics
    {
        public TimeSpan? DiscoveryToPatchWindow { get; set; }
        public int? DaysInWindow => DiscoveryToPatchWindow?.TotalDays;
        public string WindowCategory => 
            DaysInWindow switch
            {
                null => "Unknown",
                < 7 => "<1 week",
                >= 7 and < 30 => "1-4 weeks",
                >= 30 and < 90 => "1-3 months",
                >= 90 => ">3 months",
                _ => "Unknown"
            };

        public bool IsCriticalWindow => DaysInWindow.HasValue && DaysInWindow.Value > 90;
    }

    /// <summary>
    /// Source information for where a CVE was discovered.
    /// </summary>
    public class SourceInfo
    {
        public string Name { get; set; } = "";
        public DateTime? ReceivedDate { get; set; }
        public string Format => "json"; // json, csv, xml, text

        public static SourceInfo FromNvdJson(string sourceName) 
            => new() { Name = sourceName };
    }

    /// <summary>
    /// Main CVE ingestion engine.
    /// </summary>
    public class CveIngestionEngine
    {
        private readonly IngestionConfig _config;
        private readonly HashSet<string> _seenIds = new(StringComparer.OrdinalIgnoreCase);
        
        public event Action<CveRecord>? OnRecordParsed;
        public event Action<int, int>? OnBatchComplete;

        public CveIngestionEngine(IngestionConfig? config = null) 
            => _config = config ?? new IngestionConfig();

        /// <summary>
        /// Main entry point for ingesting a stream of CVE records.
        /// </summary>
        public async Task<List<CveRecord>> IngestAsync(IEnumerable<RawCveInput> inputs, SourceInfo source)
        {
            var results = new List<CveRecord>();
            int totalProcessed = 0;

            foreach (var input in inputs)
            {
                if (_config.MaxRecordsPerBatch > 0 && 
                    totalProcessed % _config.MaxRecordsPerBatch == 0)
                {
                    await Task.Delay(10); // Batch boundary breathing room
                }

                var record = ParseRecord(input, source);
                
                if (record.IsValid)
                {
                    results.Add(record);
                    OnRecordParsed?.Invoke(record);
                    totalProcessed++;
                }
            }

            OnBatchComplete?.Invoke(totalProcessed, results.Count);
            return results;
        }

        /// <summary>
        /// Parses a single raw input into a CveRecord.
        /// </summary>
        public CveRecord ParseRecord(RawCveInput input, SourceInfo source)
        {
            var record = new CveRecord();
            
            // Extract CVE ID - most critical field
            if (TryExtractId(input.Text, out string id))
                record.Id = id;

            // Try to extract discovery date from various formats
            if (!record.DiscoveryDate.HasValue)
            {
                var discovered = TryExtractDiscoveryDate(input.Text);
                if (discovered != null)
                    record.DiscoveryDate = discovered.Value;
            }

            // Extract package and version info
            if (TryExtractPackageInfo(input.Text, out string pkg, out string ver))
            {
                record.PackageName = pkg;
                record.VersionRange = ver;
            }

            // Extract CVSS score from description or metadata fields
            var cvssMatch = Regex.Match(input.Text, @"CVSS\s*[:\s]*([0-9.]+)");
            if (cvssMatch.Success)
            {
                record.CvssScore = cvssMatch.Groups[1].Value;
            }

            // Extract severity classification
            var severityMatch = Regex.Match(input.Text, @"severity\s*[:\s]*([A-Za-z0-9\-_]+)", 
                RegexOptions.IgnoreCase);
            if (severityMatch.Success)
            {
                record.Severity = severityMatch.Groups[1].Value;
            }

            // Fallback: use description as last resort
            if (!string.IsNullOrWhiteSpace(input.Text))
            {
                record.Description = input.Text.Length > 500 
                    ? input.Text[..500] + "..." 
                    : input.Text;
            }

            // Calculate metrics
            record.Metrics = CalculateMetrics(record);

            return record;
        }

        /// <summary>
        /// Tries to extract CVE ID from text. Returns true if successful.
        /// </summary>
        private static bool TryExtractId(string text, out string id)
        {
            // Pattern: CVE-YYYY-NNNNN or similar variants
            var pattern = @"CVE[-\s]?\d{4}[-\s]\d{5}(?:[-\s]\w+)?";
            
            var match = Regex.Match(text, pattern);
            if (match.Success)
            {
                id = "CVE-" + match.Groups[0].Value;
                return true;
            }

            // Fallback: look for any CVE- prefix followed by digits
            match = Regex.Match(text, @"CVE[-\s]?\d{4}[-\s]\d+");
            if (match.Success)
            {
                id = "CVE-" + match.Groups[0].Value;
                return true;
            }

            id = "";
            return false;
        }

        /// <summary>
        /// Tries to extract discovery date from text.
        /// </summary>
        private static DateTime? TryExtractDiscoveryDate(string text)
        {
            // Look for "discovered" or "published" followed by a date
            var patterns = new[]
            {
                @"(discovered|published)\s*[:\s]*([0-9]{4}-[0-9]{2}-[0-9]{2})",
                @"(found|reported)\s*on\s*([0-9]{4}-[0-9]{2}-[0-9]{2})"
            };

            foreach (var pattern in patterns)
            {
                var match = Regex.Match(text, pattern);
                if (match.Success)
                {
                    // Try to parse the date found
                    if (DateTime.TryParseExact(match.Groups[2].Value, 
                            "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var dt))
                    {
                        return dt;
                    }
                }
            }

            // Fallback: look for any date near common keywords
            var dateKeywords = new[] { "discovered", "published", "found", "reported" };
            
            foreach (var keyword in dateKeywords)
            {
                var startIdx = text.IndexOf(keyword, StringComparison.OrdinalIgnoreCase);
                if (startIdx >= 0 && startIdx + keyword.Length < text.Length - 20)
                {
                    // Look ahead for a date pattern
                    var remaining = text.Substring(startIdx + keyword.Length).Trim();
                    
                    // Try common date formats
                    foreach (var fmt in new[] 
                        { "yyyy-MM-dd", "MM/dd/yyyy", "dd/MM/yyyy", "MMM dd, yyyy" })
                    {
                        if (DateTime.TryParseExact(remaining, fmt, CultureInfo.InvariantCulture, 
                                DateTimeStyles.None, out var dt))
                        {
                            return dt;
                        }
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Tries to extract package name and version range.
        /// </summary>
        private static bool TryExtractPackageInfo(string text, out string pkg, out string ver)
        {
            pkg = "";
            ver = "";

            // Look for common patterns like "package:version" or "pkg >= 1.0 < 2.0"
            var patterns = new[]
            {
                @"(?:\b[a-zA-Z][a-zA-Z0-9\-_]*\s*[:=]\s*)?([a-zA-Z][a-zA-Z0-9\-_.]+)\s*(?:>=|<=|>|<|=)?\s*([^\s,;]+)",
                @"(?:\b[a-zA-Z][a-zA-Z0-9\-_]*\s*[:=]\s*)?([a-zA-Z][a-zA-Z0-9\-_.]+)\s+([><=!]+\s*[^\s,;]+)"
            };

            foreach (var pattern in patterns)
            {
                var match = Regex.Match(text, pattern);
                if (match.Success)
                {
                    pkg = match.Groups[1].Value;
                    
                    // Try to normalize the version range
                    if (!string.IsNullOrEmpty(match.Groups[2].Value))
                    {
                        ver = NormalizeVersionRange(match.Groups[2].Value);
                    }

                    return !string.IsNullOrEmpty(pkg) || !string.IsNullOrEmpty(ver);
                }
            }

            // Fallback: look for any package-like pattern with version operator
            match = Regex.Match(text, @"([a-zA-Z][a-zA-Z0-9\-_.]+)\s*(>=|<=|>|<|=)?\s*([^,\s;]+)");
            if (match.Success)
            {
                pkg = match.Groups[1].Value;
                ver = NormalizeVersionRange(match.Groups[3].Value);
                return !string.IsNullOrEmpty(pkg) || !string.IsNullOrEmpty(ver);
            }

            return false;
        }

        /// <summary>
        /// Normalizes a version range string into a canonical form.
        /// </summary>
        private static string NormalizeVersionRange(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return "";

            // Trim and normalize whitespace
            var normalized = input.Trim();

            // Handle common operators
            var operators = new[] { ">", "<", ">=", "<=" };
            
            foreach (var op in operators)
            {
                var parts = Regex.Split(normalized, $@"\s*{op}\s*", RegexOptions.IgnoreCase);
                if (parts.Length >= 2 && !string.IsNullOrEmpty(parts[0]))
                {
                    // First part is likely the package name
                    string pkgName = parts[0].Trim();
                    
                    // Second part might be version or another operator
                    var rest = parts[1];
                    
                    // Check if second part starts with a number (version)
                    if (Regex.IsMatch(rest, @"^\d"))
                    {
                        return $"{pkgName} {op} {rest.Trim()}";
                    }
                }
            }

            // If no operator found, assume it's just a version string
            var versionMatch = Regex.Match(normalized, @"([0-9]+(?:\.[0-9]+)*)(?:[-+][^\s]*)?");
            if (versionMatch.Success)
            {
                return versionMatch.Groups[1].Value;
            }

            // Return original trimmed input
            return normalized;
        }

        /// <summary>
        /// Calculates patch window metrics for a record.
        /// </summary>
        private static PatchWindowMetrics CalculateMetrics(CveRecord record)
        {
            var metrics = new PatchWindowMetrics();

            if (record.DiscoveryDate.HasValue && record.PatchReleaseDate.HasValue)
            {
                // Ensure discovery is before patch release
                var delta = record.PatchReleaseDate.Value - record.DiscoveryDate.Value;
                
                if (delta.TotalDays >= 0)
                {
                    metrics.DiscoveryToPatchWindow = delta;
                }
            }

            return metrics;
        }

        /// <summary>
        /// Deduplicates records by normalized ID + version range.
        /// </summary>
        public CveRecord? GetOrAddDeduped(CveRecord record)
        {
            var key = $"{record.Id}|{NormalizeVersionRange(record.VersionRange)}";

            if (_seenIds.Contains(key))
                return null; // Already seen

            _seenIds.Add(key);
            return record;
        }

        /// <summary>
        /// Reads CVE records from a file in NVD JSON format.
        /// </summary>
        public async Task<List<CveRecord>> ReadFromNvdJsonAsync(string filePath, SourceInfo source)
        {
            if (!File.Exists(filePath))
                return new List<CveRecord>();

            var json = await File.ReadAllTextAsync(filePath);
            
            // Simple JSON parsing for NVD format (no external dependency)
            try
            {
                var records = ParseNvdJson(json, source);
                return records;
            }
            catch
            {
                // Fallback: treat as plain text
                var rawInputs = new[] { RawCveInput.Create(json, "text") };
                return await IngestAsync(rawInputs, source);
            }
        }

        /// <summary>
        /// Reads CVE records from a CSV file.
        /// </summary>
        public async Task<List<CveRecord>> ReadFromCsvAsync(string filePath, 
            string idColumn = "cve_id", 
            SourceInfo? source = null)
        {
            if (!File.Exists(filePath))
                return new List<CveRecord>();

            var lines = await File.ReadAllLinesAsync(filePath);
            
            // Skip header line
            if (lines.Length <= 1)
                return new List<CveRecord>();

            var records = new List<CveRecord>();
            var headers = lines[0].Split(new[] { ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            
            int idIndex = Array.IndexOf(headers, idColumn, StringComparison.OrdinalIgnoreCase);
            if (idIndex < 0)
                return new List<CveRecord>();

            // Create source info from file path
            var src = source ?? SourceInfo.FromNvdJson(Path.GetFileName(filePath));

            foreach (var line in lines.Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var parts = line.Split(new[] { ',', ';', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                
                // Extract ID from the id column
                string? idValue = null;
                for (int i = 0; i < parts.Length && i < headers.Length; i++)
                {
                    if (headers[i].Trim().Equals(idColumn, StringComparison.OrdinalIgnoreCase))
                    {
                        idValue = parts[i];
                        break;
                    }
                }

                if (!string.IsNullOrEmpty(idValue))
                {
                    var input = RawCveInput.Create(line, "csv");
                    var record = ParseRecord(input, src);
                    
                    // Extract ID from the CSV field as fallback
                    if (TryExtractId(idValue, out string extractedId) && 
                        !record.Id.Contains(extractedId))
                    {
                        record.Id = extractedId;
                    }

                    records.Add(record);
                }
            }

            return records;
        }

        /// <summary>
        /// Reads CVE records from plain text format.