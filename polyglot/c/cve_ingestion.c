#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#define MAX_CVE_RECORDS 1024
#define MAX_LINE_LEN 8192
#define MAX_DESC_LEN 65536
#define MAX_DATE_STR 64

/* CVE record structure */
typedef struct {
    char id[64];
    char description[MAX_DESC_LEN];
    time_t published;
    time_t modified;
    int severity;          /* 0-10 scale */
    char cvss_version[8];
    double cvss_score;
    char affected_products[512];
    char references[4][MAX_LINE_LEN];
    int ref_count;
} CveRecord;

/* Global state */
static CveRecord records[MAX_CVE_RECORDS];
static int record_count = 0;

/* Trim whitespace from string in place, return new length */
static size_t trim_inplace(char *str) {
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    
    if (*start == '\0') return 0;
    
    char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)*(end - 1))) end--;
    
    size_t len = (size_t)(end - start);
    memmove(str, start, len);
    str[len] = '\0';
    return len;
}

/* Parse ISO date string to time_t */
static int parse_iso_date(const char *date_str, time_t *result) {
    if (!date_str || !*date_str) return 0;
    
    /* Try YYYY-MM-DD format first */
    struct tm tm = {0};
    int year, month, day;
    
    if (sscanf(date_str, "%d-%d-%d", &year, &month, &day) == 3) {
        tm.tm_year = year - 1900;
        tm.tm_mon = month - 1;
        tm.tm_mday = day;
        tm.tm_hour = 12; /* Assume noon for timezone safety */
        tm.tm_min = 0;
        tm.tm_sec = 0;
        *result = mktime(&tm);
        return 1;
    }
    
    /* Try YYYY-MM-DDTHH:MM:SS format */
    if (sscanf(date_str, "%d-%d-%dT%d:%d:%d", 
                 &year, &month, &day, &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        tm.tm_year = year - 1900;
        tm.tm_mon = month - 1;
        tm.tm_mday = day;
        *result = mktime(&tm);
        return 1;
    }
    
    /* Try epoch timestamp */
    if (sscanf(date_str, "%ld", result) == 1) {
        return 1;
    }
    
    return 0;
}

/* Parse severity string to numeric score */
static int parse_severity(const char *str) {
    if (!str || !*str) return 5; /* Default medium */
    
    size_t len = strlen(str);
    for (size_t i = 0; i < len && isspace((unsigned char)str[i]); i++) {}
    
    if (len - i <= 2) {
        int val = atoi(str + i);
        if (val >= 0 && val <= 10) return val;
    }
    
    /* Parse severity keywords */
    const char *keywords[] = {"Critical", "High", "Medium", "Low", "Negligible"};
    int scores[] = {10, 8, 5, 3, 1};
    
    for (int i = 0; i < 5; i++) {
        if (!strcasecmp(str + i, keywords[i])) return scores[i];
    }
    
    /* Try case-insensitive match */
    char *lower = malloc(len + 1);
    if (lower) {
        strcpy(lower, str + i);
        for (size_t j = 0; lower[j]; j++) lower[j] = tolower((unsigned char)lower[j]);
        
        for (int k = 0; k < 5; k++) {
            char *kw_lower = malloc(strlen(keywords[k]) + 1);
            strcpy(kw_lower, keywords[k]);
            for (size_t j = 0; kw_lower[j]; j++) kw_lower[j] = tolower((unsigned char)kw_lower[j]);
            
            if (!strcmp(lower, kw_lower)) {
                free(kw_lower);
                free(lower);
                return scores[k];
            }
            free(kw_lower);
        }
        free(lower);
    }
    
    /* Default to medium */
    return 5;
}

/* Extract CVE ID from line (handles various formats) */
static int extract_cve_id(const char *line, char *id_out, size_t id_size) {
    if (!line || !*line) return 0;
    
    /* Look for patterns like "CVE-2024-1234" or "cve-2024-1234" */
    const char *pattern = "CVE-[0-9]{4}-[0-9]+";
    char search_pattern[MAX_LINE_LEN];
    
    /* Build regex-like pattern for sscanf */
    if (sscanf(line, "%[^C]CVE-%d-%d", id_out, &id_out[5], &id_out[10]) >= 2) {
        return 1;
    }
    
    /* Try simpler approach: find CVE- prefix and extract following chars */
    const char *p = strstr(line, "CVE-");
    if (p && p < line + strlen(line) - 5) {
        size_t start = p - line;
        int year, rest;
        
        /* Extract 4-digit year */
        if (sscanf(p + 4, "%d", &year) == 1) {
            /* Check for valid format: CVE-YYYY-NNNNN where N is digit */
            char temp[64];
            strncpy(temp, p + 9, 5);
            temp[5] = '\0';
            
            if (strlen(temp) >= 2 && isdigit((unsigned char)temp[0])) {
                /* Found valid CVE ID format */
                strncpy(id_out, p, start + strlen("CVE-") + 4 + 9);
                id_out[start + 13] = '\0';
                return 1;
            }
        }
    }
    
    return 0;
}

/* Parse a single CVE record from structured input */
static int parse_cve_record(const char *line, CveRecord *rec) {
    memset(rec, 0, sizeof(*rec));
    
    /* Extract CVE ID */
    if (extract_cve_id(line, rec->id, sizeof(rec->id))) {
        return 1;
    }
    
    /* If we got an ID, assume this is a record line and extract other fields */
    if (*rec->id) {
        /* Try to find description - look for "Description:" or "DESC:" prefix */
        const char *desc_start = strstr(line, "Description:");
        if (!desc_start) desc_start = strstr(line, "DESC:");
        
        if (desc_start && desc_start < line + strlen(line) - 100) {
            size_t len = strlen(desc_start);
            for (size_t i = 0; i < len && isspace((unsigned char)desc_start[i]); i++) {}
            
            if (i < len - 50) {
                strncpy(rec->description, desc_start + i, MAX_DESC_LEN - 1);
                trim_inplace(rec->description);
            }
        }
        
        /* Try to find dates */
        const char *pub = strstr(line, "Published:");
        if (pub && parse_iso_date(pub + 9, &rec->published)) {
            rec->modified = rec->published;
        } else {
            pub = strstr(line, "Modified:");
            if (pub && parse_iso_date(pub + 9, &rec->modified)) {
                rec->published = rec->modified - 86400; /* Assume published before modified */
            }
        }
        
        /* Try to find severity */
        const char *sev = strstr(line, "Severity:");
        if (sev) {
            size_t len = strlen(sev);
            for (size_t i = 0; i < len && isspace((unsigned char)sev[i]); i++) {}
            
            if (i < len - 10) {
                rec->severity = parse_severity(sev + i);
            }
        }
        
        /* Try to find CVSS */
        const char *cvss = strstr(line, "CVSS:");
        if (cvss && cvss < line + strlen(line) - 50) {
            size_t len = strlen(cvss);
            for (size_t i = 0; i < len && isspace((unsigned char)cvss[i]); i++) {}
            
            if (i < len - 10) {
                strncpy(rec->cvss_version, cvss + i, sizeof(rec->cvss_version) - 1);
                
                /* Try to extract score */
                double score;
                if (sscanf(cvss + i, "%lf", &score) == 1 && score >= 0.0 && score <= 10.0) {
                    rec->cvss_score = score;
                }
            }
        }
    }
    
    return (*rec).id[0] != '\0';
}

/* Parse references section */
static int parse_references(const char *line, CveRecord *rec) {
    if (!rec || !rec->id[0]) return 0;
    
    /* Look for "References:" or "REFS:" prefix */
    const char *ref_start = strstr(line, "References:");
    if (!ref_start) ref_start = strstr(line, "REFS:");
    
    if (ref_start && ref_start < line + strlen(line) - 20) {
        size_t len = strlen(ref_start);
        for (size_t i = 0; i < len && isspace((unsigned char)ref_start[i]); i++) {}
        
        /* Try to extract up to 4 references */
        int ref_idx = 0;
        const char *p = ref_start + i;
        
        while (*p && ref_idx < 4) {
            /* Skip whitespace and newlines */
            while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
            
            if (!*p) break;
            
            /* Check for reference URL or email */
            if (strncmp(p, "https://", 8) == 0 || 
                strncmp(p, "http://", 7) == 0 ||
                strncmp(p, "mailto:", 7) == 0) {
                
                size_t url_len = strlen(p);
                for (size_t j = 0; j < url_len && isspace((unsigned char)p[j]); j++) {}
                
                if (j + 50 <= len - i) {
                    strncpy(rec->references[ref_idx], p + j, MAX_LINE_LEN - 1);
                    trim_inplace(rec->references[ref_idx]);
                    ref_idx++;
                }
            } else if (isalnum((unsigned char)*p)) {
                /* Could be a reference ID or other format */
                size_t word_len = 0;
                while (*p && isalnum((unsigned char)*p) && *p != ':' && *p != ' ') {
                    p++;
                    word_len++;
                }
                
                if (word_len >= 3) {
                    strncpy(rec->references[ref_idx], rec->id, MAX_LINE_LEN - 1);
                    trim_inplace(rec->references[ref_idx]);
                    ref_idx++;
                }
            } else {
                p++;
            }
        }
        
        rec->ref_count = ref_idx;
    }
    
    return rec->ref_count > 0;
}

/* Validate a parsed CVE record */
static int validate_cve_record(const CveRecord *rec) {
    if (!rec || !*rec->id) return 0;
    
    /* Check ID format: CVE-YYYY-NNNNN */
    char id_copy[64];
    strncpy(id_copy, rec->id, sizeof(id_copy));
    trim_inplace(id_copy);
    
    int year, rest;
    if (sscanf(id_copy, "CVE-%d-%d", &year, &rest) == 2 && 
        year >= 1980 && year <= 2100 &&
        rest > 0 && rest < 100000) {
        return 1;
    }
    
    /* Check for reasonable description */
    size_t desc_len = strlen(rec->description);
    if (desc_len >= 50 || rec->severity != 5) {
        return 1;
    }
    
    /* Check dates are not absurd */
    time_t now = time(NULL);
    if (rec->published > 0 && 
        rec->published < now + 365 * 86400 &&
        rec->modified >= rec->published) {
        return 1;
    }
    
    /* Check severity is in range */
    if (rec->severity >= 0 && rec->severity <= 10) {
        return 1;
    }
    
    return 0;
}

/* Add a record to the collection, deduplicating by ID */
static int add_record(const CveRecord *new_rec) {
    if (!new_rec || !*new_rec->id) return 0;
    
    /* Check for existing record with same ID */
    for (int i = 0; i < record_count; i++) {
        if (!strcmp(records[i].id, new_rec->id)) {
            /* Merge: keep newer dates, update severity if higher */
            if (new_rec->published > records[i].published) {
                records[i].published = new_rec->published;
            }
            if (new_rec->modified > records[i].modified) {
                records[i].modified = new_rec->modified;
            }
            if (new_rec->severity > records[i].severity) {
                records[i].severity = new_rec->severity;
            }
            
            /* Merge descriptions */
            size_t desc_len = strlen(records[i].description);
            for (size_t j = 0; j < desc_len && isspace((unsigned char)records[i].description[j]); j++) {}
            
            if (desc_len > 0) {
                strncpy(records[i].description, records[i].description + j, MAX_DESC_LEN - 1);
                trim_inplace(records[i].description);
            }
            
            return 1; /* Merged */
        }
    }
    
    /* Add new record if space available */
    if (record_count < MAX_CVE_RECORDS) {
        memcpy(&records[record_count], new_rec, sizeof(*new_rec));
        record_count++;
        return 1;
    }
    
    return 0;
}

/* Process a line of input - returns 1 if a record was added */
static int process_line(const char *line) {
    CveRecord rec;
    
    /* Skip empty lines and comments */
    size_t len = strlen(line);
    for (size_t i = 0; i < len && isspace((unsigned char)line[i]); i++) {}
    
    if (!*line || line[0] == '#' || line[0] == ';') {
        return 0;
    }
    
    /* Try to parse as structured record */
    if (parse_cve_record(line, &rec)) {
        if (validate_cve_record(&rec)) {
            add_record(&rec);
            return 1;
        }
    }
    
    /* Fallback: try line-based parsing for semi-structured input */
    if (!*rec.id) {
        /* Look for CVE ID anywhere in the line */
        char id_buf[64];
        if (extract_cve_id(line, id_buf, sizeof(id_buf))) {
            strncpy(rec.id, id_buf, sizeof(rec.id));
            
            /* Try to find description after the ID */
            const char *after_id = strstr(line, rec.id);
            if (after_id) {
                size_t start = after_id - line + strlen(rec.id);
                for (size_t i = 0; i < len && isspace((unsigned char)line[start + i]); i++) {}
                
                if (start + i < len - 50) {
                    strncpy(rec.description, line + start + i, MAX_DESC_LEN - 1);
                    trim_inplace(rec.description);
                    
                    if (strlen(rec.description) > 20 || rec.severity != 5) {
                        add_record(&rec);
                        return 1;
                    }
                }
            }
        }
    }
    
    return 0;
}

/* Process a file and collect CVE records */
static int process_file(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Could not open file '%s'\n", filename);
        return -1;
    }
    
    char line[MAX_LINE_LEN];