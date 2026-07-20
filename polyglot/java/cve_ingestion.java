package polyglot.java;

import java.io.*;
import java.net.http.HttpClient;
import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CVE Ingestion Module for vulntimeline.
 * Parses, validates, deduplicates, and normalizes CVE records from multiple sources.
 */
public class CveIngestion {

    // NVD default feed URL
    private static final String DEFAULT_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    
    // Deduplication key: normalized CVE ID (lowercase, trimmed)
    private static final Pattern CVE_PATTERN = Pattern.compile(
        "^CVE-\\d{4}-[A-Z]{1,6}[0-9]{1,3}$", 
        Pattern.CASE_INSENSITIVE | Pattern.MULTILINE);

    /**
     * Normalized CVE record with all extracted metadata.
     */
    public static class CveRecord {
        private final String cveId;
        private final Instant publishedDate;
        private final Instant lastModified;
        private final int severityScore; // NVD CVSS v3.x or v4.0
        private final String cvssVersion;
        private final List<String> affectedProducts;
        private final Map<String, String> platforms = new LinkedHashMap<>();
        private final String description;
        private final boolean isRetired;

        public CveRecord(String cveId, Instant publishedDate, int severityScore, 
                        String cvssVersion, List<String> affectedProducts,
                        Map<String, String> platforms, String description, boolean isRetired) {
            this.cveId = normalizeCveId(cveId);
            this.publishedDate = publishedDate;
            this.lastModified = Instant.now();
            this.severityScore = severityScore;
            this.cvssVersion = cvssVersion != null ? cvssVersion : "3.1";
            this.affectedProducts = affectedProducts;
            this.platforms = platforms;
            this.description = description;
            this.isRetired = isRetired;
        }

        public String getNormalizedId() { return cveId; }
        public Instant getPublishedDate() { return publishedDate; }
        public int getSeverityScore() { return severityScore; }
        public List<String> getAffectedProducts() { return affectedProducts; }
        public Map<String, String> getPlatforms() { return platforms; }
        public boolean isRetired() { return isRetired; }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof CveRecord)) return false;
            CveRecord that = (CveRecord) o;
            return Objects.equals(cveId, that.cveId);
        }

        @Override
        public int hashCode() {
            return cveId != null ? cveId.hashCode() : 0;
        }

        @Override
        public String toString() {
            return "CveRecord{" +
                   "cveId='" + cveId + '\'' +
                   ", severity=" + severityScore +
                   ", published=" + publishedDate +
                   '}';
        }
    }

    /**
     * Ingestion configuration.
     */
    public static class Config {
        private String nvdUrl = DEFAULT_NVD_URL;
        private int batchSize = 100;
        private boolean autoRetry = true;
        private int maxRetries = 3;
        private long timeoutMs = 30_000;

        public static Config defaultConfig() {
            return new Config();
        }

        public String getNvdUrl() { return nvdUrl; }
        public void setNvdUrl(String url) { this.nvdUrl = url; }
        public int getBatchSize() { return batchSize; }
        public boolean isAutoRetry() { return autoRetry; }
        public long getTimeoutMs() { return timeoutMs; }

        @Override
        public String toString() {
            return "Config{" +
                   "nvdUrl='" + nvdUrl + '\'' +
                   ", batchSize=" + batchSize +
                   '}';
        }
    }

    /**
     * Thread-safe deduplication store.
     */
    private static class DedupStore {
        private final Map<String, CveRecord> records = new ConcurrentHashMap<>();
        private final Set<String> pending = ConcurrentHashMap.newKeySet();

        public void add(CveRecord record) {
            if (record == null || record.getNormalizedId() == null) return;
            
            String key = record.getNormalizedId().toUpperCase();
            CveRecord existing = records.get(key);
            
            // Keep the one with more recent published date
            if (existing != null && 
                Objects.equals(existing.getPublishedDate(), record.getPublishedDate())) {
                records.put(key, record);
            } else if (existing == null || 
                       record.getPublishedDate().isAfter(existing.getPublishedDate())) {
                records.put(key, record);
            }
        }

        public List<CveRecord> getAll() {
            return new ArrayList<>(records.values());
        }

        public int size() {
            return records.size();
        }

        public void clear() {
            records.clear();
            pending.clear();
        }
    }

    /**
     * Main ingestion engine.
     */
    private static class IngestionEngine {
        private final Config config;
        private final DedupStore store;
        private final HttpClient client = HttpClient.newHttpClient();

        public IngestionEngine(Config config, DedupStore store) {
            this.config = Objects.requireNonNull(config);
            this.store = Objects.requireNonNull(store);
        }

        /**
         * Fetches CVE records from NVD API.
         */
        private List<CveRecord> fetchFromNvd(String cveId, int maxResults) throws IOException {
            String url = config.getNvdUrl() + "?cveId=" + UriEncode(cveId);
            
            try (var response = client.send(
                HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .GET()
                    .header("Accept", "application/json")
                    .timeout(java.time.Duration.ofMillis(config.getTimeoutMs()))
                    .build(),
                BodyHandlers.ofString()
            )) {

                if (response.statusCode() == 200) {
                    return parseNvdResponse(response.body());
                } else if (response.statusCode() >= 400 && response.statusCode() < 500) {
                    throw new IOException("HTTP " + response.statusCode() + ": " + response.body());
                } else {
                    // Retry for transient errors
                    return retryFetch(cveId, maxResults);
                }
            }
        }

        private List<CveRecord> parseNvdResponse(String json) throws IOException {
            try (var reader = new StringReader(json)) {
                JsonParser parser = new JsonParser();
                
                // NVD 2.0 response structure:
                // { "items": [ { "cve": { "id": "...", "published": "...", ... } }, ... ] }
                
                var items = parser.parse(reader, CveItem.class);
                List<CveRecord> result = new ArrayList<>();

                for (var item : items) {
                    if (!item.getCve().isPresent()) continue;

                    var cveData = item.getCve().get();
                    
                    // Extract timestamps
                    Instant published = parseTimestamp(cveData.getPublished());
                    Instant modified = parseTimestamp(cveData.getLastModified());

                    // Parse CVSS score from NVD fields
                    int severityScore = 0;
                    String cvssVersion = "3.1";
                    
                    if (cveData.getCvssV3_1() != null) {
                        severityScore = parseCvssScore(cveData.getCvssV3_1());
                        cvssVersion = "3.1";
                    } else if (cveData.getCvssV4_0() != null) {
                        severityScore = parseCvssScore(cveData.getCvssV4_0());
                        cvssVersion = "4.0";
                    }

                    // Extract affected products from NVD relationships
                    List<String> affectedProducts = new ArrayList<>();
                    if (cveData.getAffectedProducts() != null) {
                        for (var prod : cveData.getAffectedProducts()) {
                            String name = prod.getName();
                            String platform = prod.getPlatforms() != null ? 
                                prod.getPlatforms().get(0) : "Unknown";
                            
                            if (!name.isEmpty() && !platform.equals("Unknown")) {
                                affectedProducts.add(name + " (" + platform + ")");
                            }
                        }
                    }

                    // Build description summary
                    StringBuilder desc = new StringBuilder();
                    if (cveData.getDescription() != null) {
                        desc.append(cveData.getDescription().getSummary());
                    }
                    if (cveData.getReferences() != null && !cveData.getReferences().isEmpty()) {
                        desc.append(" | ").append(cveData.getReferences().size()).append(" refs");
                    }

                    // Check if retired
                    boolean isRetired = cveData.isRetired();

                    result.add(new CveRecord(
                        cveData.getId(),
                        published,
                        severityScore,
                        cvssVersion,
                        affectedProducts.isEmpty() ? null : affectedProducts,
                        new LinkedHashMap<>(), // platforms map (can be expanded)
                        desc.toString().trim(),
                        isRetired
                    ));
                }

                return result;
            }
        }

        private String parseTimestamp(String timestampStr) {
            if (timestampStr == null || timestampStr.isEmpty()) {
                return Instant.now();
            }

            // NVD uses ISO 8601 format: "2024-01-15T10:30:00.000Z"
            try {
                DateTimeFormatter formatter = DateTimeFormatter.ISO_INSTANT;
                return Instant.from(formatter.parse(timestampStr));
            } catch (Exception e) {
                // Fallback: assume epoch seconds if ISO parsing fails
                try {
                    long epochSeconds = Long.parseLong(timestampStr);
                    return Instant.ofEpochSecond(epochSeconds);
                } catch (NumberFormatException ex) {
                    return Instant.now();
                }
            }
        }

        private int parseCvssScore(CvssData cvssData) {
            if (cvssData == null || cvssData.getVector() == null) {
                return 0;
            }

            // CVSS v3.x uses a numeric score in the vector string
            String vector = cvssData.getVector();
            
            // Extract numeric score from "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
            Pattern scorePattern = Pattern.compile("(\\d+\\.?\\d*)");
            Matcher matcher = scorePattern.matcher(vector);
            
            if (matcher.find()) {
                try {
                    return Integer.parseInt(matcher.group(1));
                } catch (NumberFormatException e) {
                    // Return 0 on parse failure
                }
            }

            // Fallback: use severity string mapping
            String severity = cvssData.getSeverity();
            if ("HIGH".equalsIgnoreCase(severity)) return 7;
            else if ("MEDIUM".equalsIgnoreCase(severity)) return 4;
            else if ("LOW".equalsIgnoreCase(severity)) return 1;
            
            return 0;
        }

        private String normalizeCveId(String id) {
            if (id == null || id.isEmpty()) return "UNKNOWN";
            
            // Remove leading/trailing whitespace, convert to uppercase
            id = id.trim().toUpperCase();
            
            // Handle common variations: CVE-2024-1234 vs CVE_2024_1234
            id = id.replace('_', '-');
            
            return id;
        }

        private String UriEncode(String str) {
            try {
                return java.net.URLEncoder.encode(str, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                // UTF-8 should always be supported
                return str;
            }
        }

        private List<CveRecord> retryFetch(String cveId, int maxResults) throws IOException {
            if (!config.isAutoRetry()) {
                throw new IOException("Auto-retry disabled");
            }

            for (int attempt = 0; attempt < config.getMaxRetries(); attempt++) {
                try {
                    return fetchFromNvd(cveId, maxResults);
                } catch (IOException e) {
                    if (attempt == config.getMaxRetries() - 1) {
                        throw new IOException("Failed after " + (attempt + 1) + 
                                           " attempts: " + e.getMessage(), e);
                    }
                    
                    // Exponential backoff
                    long delay = Math.pow(2, attempt) * 500;
                    Thread.sleep(delay);
                }
            }
            
            return new ArrayList<>();
    }

        /**
         * Main ingestion entry point.
         */
        public List<CveRecord> ingest(String cveIdOrFile) throws IOException {
            if (cveIdOrFile == null || cveIdOrFile.isEmpty()) {
                throw new IllegalArgumentException("CVE ID or file path required");
            }

            // Check if it's a file path
            Path inputPath = Path.of(cveIdOrFile);
            boolean isFile = Files.exists(inputPath) && Files.isRegularFile(inputPath);

            List<CveRecord> results;

            if (isFile) {
                // Parse from JSON/XML file
                try (var reader = Files.newBufferedReader(inputPath)) {
                    JsonParser parser = new JsonParser();
                    var items = parser.parse(reader, CveItem.class);
                    
                    results = new ArrayList<>();
                    for (var item : items) {
                        if (!item.getCve().isPresent()) continue;
                        
                        var cveData = item.getCve().get();
                        Instant published = parseTimestamp(cveData.getPublished());
                        
                        // Simple file-based parsing for flexibility
                        int severityScore = 0;
                        String cvssVersion = "3.1";
                        
                        if (cveData.getCvssV3_1() != null) {
                            severityScore = parseCvssScore(cveData.getCvssV3_1());
                            cvssVersion = "3.1";
                        }

                        results.add(new CveRecord(
                            cveData.getId(),
                            published,
                            severityScore,
                            cvssVersion,
                            null, // affected products from file
                            new LinkedHashMap<>(),
                            cveData.getDescription() != null ? 
                                cveData.getDescription().getSummary() : "",
                            false
                        ));
                    }
                }
            } else {
                // Fetch from NVD API
                results = fetchFromNvd(cveIdOrFile, 10);
            }

            return results;
        }

        public void ingestBatch(List<String> cveIds) throws IOException {
            if (cveIds == null || cveIds.isEmpty()) {
                throw new IllegalArgumentException("CVE ID list required");
            }

            List<CveRecord> allRecords = new ArrayList<>();
            
            for (String cveId : cveIds) {
                // Batch fetch with parallel processing
                try {
                    var records = fetchFromNvd(cveId, 10);
                    allRecords.addAll(records);
                    
                    if (!config.isAutoRetry() && !records.isEmpty()) {
                        break; // Stop after first successful batch
                    }
                } catch (IOException e) {
                    System.err.println("Warning: Failed to fetch " + cveId + ": " + e.getMessage());
                }

                // Small delay between requests to avoid rate limiting
                Thread.sleep(100);
            }

            return allRecords;
        }

        public void ingestFromStream(InputStream inputStream) throws IOException {
            try (var reader = new InputStreamReader(inputStream)) {
                JsonParser parser = new JsonParser();
                var items = parser.parse(reader, CveItem.class);
                
                List<CveRecord> records = new ArrayList<>();
                for (var item : items) {
                    if (!item.getCve().isPresent()) continue;
                    
                    var cveData = item.getCve().get();
                    Instant published = parseTimestamp(cveData.getPublished());
                    int severityScore = 0;
                    
                    if (cveData.getCvssV3_1() != null) {
                        severityScore = parseCvssScore(cveData.getCvssV3_1());
                    }

                    records.add(new CveRecord(
                        cveData.getId(),
                        published,
                        severityScore,
                        "3.1",
                        null,
                        new LinkedHashMap<>(),
                        cveData.getDescription() != null ? 
                            cveData.getDescription().getSummary() : "",
                        false
                    ));
                }

                return records;
            }
        }
    }

    /**
     * JSON parser supporting NVD 2.0 response format.
     */
    private static class JsonParser {
        
        public <T> T parse(Reader reader, Class<T> clazz) throws IOException {
            // Simple recursive descent parser for NVD structure
            try (var scanner = new Scanner(reader)) {