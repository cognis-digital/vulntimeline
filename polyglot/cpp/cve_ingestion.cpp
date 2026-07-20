// polyglot/cpp/cve_ingestion.cpp
// Vulnerability disclosure timeline builder - CVE ingestion module
// Complete, self-contained implementation

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <algorithm>
#include <chrono>
#include <iomanip>
#include <regex>
#include <filesystem>

namespace fs = std::filesystem;

// ============================================================================
// Data Structures
// ============================================================================

struct CveRecord {
    std::string id;
    std::string summary;
    std::string description;
    std::string affected_products;
    std::string severity;
    std::map<std::string, std::string> references;
    
    // Dates (ISO 8601 strings)
    std::string publish_date;
    std::string last_modified;
    std::string patch_published;
    std::string patch_available;
    
    // Metadata
    int cvss_score = 0.0f;
    bool is_exploit_available = false;
    int affected_versions_count = 0;
};

struct IngestionStats {
    size_t total_records = 0;
    size_t parsed_successfully = 0;
    size_t parse_errors = 0;
    size_t duplicates_found = 0;
    size_t validation_warnings = 0;
    
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace utils {

constexpr const char* CVE_ID_REGEX = "CVE-\\d{4}-[0-9A-Fa-f]{4,12}";

bool isValidCveId(const std::string& id) {
    static std::regex pattern(CVE_ID_REGEX);
    return std::regex_match(id, pattern);
}

std::string normalizeDate(const std::string& dateStr) {
    // Try to parse and normalize various date formats
    auto fmt = "%Y-%m-%d";
    auto fmt2 = "%Y-%m-%dT%H:%M:%SZ";
    
    if (dateStr.empty()) return "";
    
    // Return as-is for now; caller can use chrono::parse if needed
    return dateStr;
}

std::string trim(const std::string& str) {
    auto start = str.find_first_not_of(" \t\r\n");
    auto end = str.find_last_not_of(" \t\r\n");
    return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

std::vector<std::string> split(const std::string& str, char delimiter) {
    std::vector<std::string> result;
    std::stringstream ss(str);
    std::string item;
    
    while (std::getline(ss, item, delimiter)) {
        if (!item.empty()) {
            result.push_back(item);
        }
    }
    return result;
}

// ============================================================================
// CVE Record Parser
// ============================================================================

class CveParser {
public:
    enum class FormatType { AUTO, NVD_JSON, NIST_XML, TEXT };
    
private:
    std::string rawContent;
    FormatType detectedFormat = FormatType::AUTO;
    
    // Helper to extract JSON string value
    static std::string extractJsonString(const std::string& json, const std::string& key) {
        auto start = json.find("\"" + key + "\"");
        if (start == std::string::npos) return "";
        
        start = json.find(':', start);
        if (start == std::string::npos) return "";
        
        start = json.find('"', start + 1);
        if (start == std::string::npos) return "";
        
        auto end = json.find('"', start + 1);
        return (end != std::string::npos) ? json.substr(start + 1, end - start - 1) : "";
    }

public:
    CveParser() = default;
    
    void setRawContent(const std::string& content) {
        rawContent = content;
    }
    
    FormatType detectFormat() const {
        if (rawContent.empty()) return FormatType::AUTO;
        
        // Check for NVD JSON structure
        auto jsonCheck1 = rawContent.find("\"cveMetadata\"");
        auto jsonCheck2 = rawContent.find("\"datastream:format\":\"JSON\"");
        auto xmlCheck = rawContent.find("<?xml");
        
        if (jsonCheck1 != std::string::npos || jsonCheck2 != std::string::npos) {
            return FormatType::NVD_JSON;
        } else if (xmlCheck != std::string::npos) {
            return FormatType::NIST_XML;
        }
        
        // Default to text for line-by-line parsing
        return FormatType::TEXT;
    }

    CveRecord parse() const {
        CveRecord record;
        auto format = detectFormat();
        
        if (format == FormatType::NVD_JSON) {
            parseJson(record);
        } else if (format == FormatType::NIST_XML) {
            // XML parsing would go here - simplified for now
            parseText(record);
        } else {
            parseText(record);
        }
        
        return record;
    }

private:
    void parseJson(CveRecord& record) const {
        // Extract CVE ID
        auto idMatch = rawContent.find("\"id\":\"");
        if (idMatch != std::string::npos) {
            auto start = rawContent.find('"', idMatch + 4);
            auto end = rawContent.find('"', start + 1);
            record.id = (end != std::string::npos) ? 
                       rawContent.substr(start + 1, end - start - 1) : "";
        }
        
        // Extract summary
        record.summary = extractJsonString(rawContent, "summary");
        
        // Extract description
        auto descStart = rawContent.find("\"description\"");
        if (descStart != std::string::npos) {
            descStart = rawContent.find('"', descStart + 12);
            auto descEnd = rawContent.find('"', descStart + 1);
            record.description = (descEnd != std::string::npos) ? 
                                rawContent.substr(descStart + 1, descEnd - descStart - 1) : "";
        }
        
        // Extract affected products
        auto prodStart = rawContent.find("\"affectedProducts\"");
        if (prodStart != std::string::npos) {
            prodStart = rawContent.find('"', prodStart + 19);
            auto prodEnd = rawContent.find('"', prodStart + 1);
            record.affected_products = (prodEnd != std::string::npos) ? 
                                      rawContent.substr(prodStart + 1, prodEnd - prodStart - 1) : "";
        }
        
        // Extract severity
        auto sevStart = rawContent.find("\"severity\"");
        if (sevStart != std::string::npos) {
            sevStart = rawContent.find('"', sevStart + 10);
            auto sevEnd = rawContent.find('"', sevStart + 1);
            record.severity = (sevEnd != std::string::npos) ? 
                             rawContent.substr(sevStart + 1, sevEnd - sevStart - 1) : "";
        }
        
        // Extract CVSS score if present
        auto cvssMatch = rawContent.find("\"cvssV3_0\"");
        if (cvssMatch != std::string::npos) {
            auto numStart = rawContent.find('"', cvssMatch + 11);
            auto numEnd = rawContent.find('"', numStart + 1);
            record.cvss_score = (numEnd != std::string::npos && !rawContent.substr(numStart + 1, 2).empty()) ? 
                               std::stof(rawContent.substr(numStart + 1, 2)) : 0.0f;
        }
        
        // Extract dates
        record.publish_date = extractJsonString(rawContent, "publishDate");
        record.last_modified = extractJsonString(rawContent, "lastModifiedDate");
    }

    void parseText(CveRecord& record) const {
        // Text format: line-based key:value or structured text
        std::istringstream iss(rawContent);
        std::string line;
        
        while (std::getline(iss, line)) {
            auto pos = line.find(':');
            if (pos == std::string::npos) continue;
            
            std::string key = trim(line.substr(0, pos));
            std::string value = trim(line.substr(pos + 1));
            
            // Map keys to fields
            if (key == "id") {
                record.id = value;
            } else if (key == "summary" || key == "title") {
                record.summary = value;
            } else if (key == "description") {
                record.description = value;
            } else if (key == "severity") {
                record.severity = value;
            } else if (key == "cvss" || key == "score") {
                try {
                    record.cvss_score = std::stof(value);
                } catch (...) {}
            } else if (key.find("date") != std::string::npos) {
                // Try to match specific date fields
                if (value.empty()) continue;
                
                auto lowerKey = key;
                std::transform(lowerKey.begin(), lowerKey.end(), 
                              lowerKey.begin(), ::tolower);
                
                if (lowerKey.find("publish") != std::string::npos) {
                    record.publish_date = value;
                } else if (lowerKey.find("modified") != std::string::npos) {
                    record.last_modified = value;
                } else if (lowerKey.find("patch") != std::string::npos) {
                    auto patchStart = lowerKey.find('p');
                    if (patchStart == 0 || patchStart == 1) { // "patch" or "patched"
                        record.patch_published = value;
                    } else if (lowerKey.find("available") != std::string::npos) {
                        record.patch_available = value;
                    }
                }
            }
        }
    }

public:
    // Parse from file path
    static CveRecord parseFromFile(const fs::path& filepath) {
        if (!fs::exists(filepath)) {
            throw std::runtime_error("File not found: " + filepath.string());
        }
        
        auto content = std::string(fs::file_size(filepath));
        std::ifstream file(filepath, std::ios::binary | std::ios::ate);
        if (file.is_open()) {
            content.resize(file.tellg());
            file.seekg(0);
            file.read(&content[0], static_cast<std::streamsize>(content.size()));
        } else {
            throw std::runtime_error("Failed to open file: " + filepath.string());
        }
        
        CveParser parser;
        parser.setRawContent(content);
        return parser.parse();
    }

    // Parse from string (for batch processing)
    static std::vector<CveRecord> parseFromBatch(const std::string& content, 
                                                  size_t expectedCount = 0) {
        CveParser parser;
        parser.setRawContent(content);
        
        auto format = parser.detectFormat();
        std::vector<CveRecord> records;
        
        if (format == FormatType::NVD_JSON || format == FormatType::NIST_XML) {
            // Single record in JSON/XML
            records.push_back(parser.parse());
        } else {
            // Text format - split by common delimiters
            std::vector<std::string> chunks;
            
            // Split by empty lines or triple dashes (common text formats)
            auto delim = [](const std::string& s, const char* d) -> size_t {
                return s.find(d);
            };
            
            auto pos = 0;
            while ((pos = delim(content, "\n\n")) != std::string::npos && 
                   !content.empty()) {
                if (pos > 0 || content.size() > 3) { // Avoid infinite loop on empty strings
                    chunks.push_back(content.substr(0, pos));
                    content.erase(0, pos + 1);
                } else {
                    break;
                }
            }
            
            // If no delimiter found, treat as single record
            if (chunks.empty()) {
                chunks.push_back(content);
            }
            
            for (auto& chunk : chunks) {
                CveParser chunkParser;
                chunkParser.setRawContent(chunk);
                
                auto format = chunkParser.detectFormat();
                if (format == FormatType::NVD_JSON || format == FormatType::NIST_XML) {
                    records.push_back(chunkParser.parse());
                } else {
                    // Try line-by-line for text chunks
                    CveRecord record;
                    std::istringstream iss(chunk);
                    std::string line;
                    
                    while (std::getline(iss, line)) {
                        auto pos = line.find(':');
                        if (pos == std::string::npos) continue;
                        
                        std::string key = trim(line.substr(0, pos));
                        std::string value = trim(line.substr(pos + 1));
                        
                        if (key == "id") record.id = value;
                        else if (key == "summary" || key == "title") record.summary = value;
                        else if (key == "description") record.description = value;
                        else if (key == "severity") record.severity = value;
                    }
                    
                    records.push_back(record);
                }
            }
        }
        
        return records;
    }

    // Parse from NVD JSONL format (one JSON object per line)
    static std::vector<CveRecord> parseJsonl(const fs::path& filepath, 
                                              IngestionStats& stats) {
        if (!fs::exists(filepath)) {
            throw std::runtime_error("File not found: " + filepath.string());
        }
        
        auto content = std::string(fs::file_size(filepath));
        std::ifstream file(filepath);
        
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open JSONL file");
        }
        
        stats.start_time = std::chrono::steady_clock::now();
        stats.total_records = 0;
        stats.parsed_successfully = 0;
        stats.parse_errors = 0;
        
        CveRecord record;
        std::string line;
        
        while (std::getline(file, line)) {
            if (line.empty()) continue;
            
            ++stats.total_records;
            
            try {
                // Extract ID from JSONL line
                auto idStart = line.find("\"id\":\"");
                if (idStart == std::string::npos) {
                    stats.parse_errors++;
                    continue;
                }
                
                auto start = line.find('"', idStart + 4);
                auto end = line.find('"', start + 1);
                record.id = (end != std::string::npos) ? 
                           line.substr(start + 1, end - start - 1) : "";
                
                if (!isValidCveId(record.id)) {
                    stats.parse_errors++;
                    continue;
                }
                
                // Extract other fields
                record.summary = extractJsonString(line, "summary");
                record.description = extractJsonString(line, "description");
                record.severity = extractJsonString(line, "severity");
                
                auto cvssMatch = line.find("\"cvssV3_0\"");
                if (cvssMatch != std::string::npos) {
                    auto numStart = line.find('"', cvssMatch + 11);
                    auto numEnd = line.find('"', numStart + 1);
                    record.cvss_score = (numEnd != std::string::npos && 
                                        !line.substr(numStart + 1, 2).empty()) ? 
                                       std::stof(line.substr(numStart + 1, 2)) : 0.0f;
                }
                
                // Extract dates
                record.publish_date = extractJsonString(line, "publishDate");
                record.last_modified = extractJsonString(line, "lastModifiedDate");
                
                ++stats.parsed_successfully;
            } catch (const std::exception& e) {
                stats.parse_errors++;
            }
        }
        
        stats.end_time = std::chrono::steady_clock::now();
        return records;
    }

};

// ============================================================================
// Ingestion Engine
// ============================================================================

class CveIngestionEngine {
public:
    struct Config {
        fs::path inputPath;
        fs::path outputDir = "";
        bool validateIds = true;
        bool removeDuplicates = true;
        size_t batchSize = 10000;
        bool progressReporting = false;
        
        // Output options
        bool writeIndividualFiles =