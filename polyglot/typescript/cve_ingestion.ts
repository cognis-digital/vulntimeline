import { CVERecord, IngestionResult, TimelineEntry, SeverityLevel } from './types';

// Constants for validation
const CVE_ID_REGEX = /^CVE-\d{4}-\d{4,7}(?:[A-Z0-9]?)?$/i;
const MIN_CVE_YEAR = 1986;
const MAX_CVE_YEAR = new Date().getFullYear() + 2;

// Severity thresholds for CVSS scores
export const SEVERITY_THRESHOLDS: Record<SeverityLevel, number> = {
    CRITICAL: 9.0,
    HIGH: 7.0,
    MEDIUM: 4.0,
    LOW: 1.0,
};

// Helper to normalize CVE ID format
function normalizeCveId(raw: string): string | null {
    if (!raw || typeof raw !== 'string') return null;
    
    // Trim and uppercase
    let normalized = raw.trim().toUpperCase();
    
    // Remove common prefixes/suffixes
    const cleanRegex = /^CVE-?/i;
    normalized = normalized.replace(cleanRegex, '');
    
    // Re-add standard prefix if missing
    if (!normalized.startsWith('CVE-')) {
        normalized = `CVE-${normalized}`;
    }
    
    // Validate format
    if (CVE_ID_REGEX.test(normalized)) return normalized;
    
    return null;
}

// Helper to parse and validate dates
function parseDate(dateStr: string | Date): Date {
    let parsed: Date;
    
    if (dateStr instanceof Date) {
        parsed = dateStr;
    } else if (typeof dateStr === 'string') {
        // Try ISO format first, then fallback to common formats
        const isoMatch = dateStr.match(/^(\d{4})-(\d{2})-(\d{2})(?:T[\d:.]+)?(?:Z|[+-]\d{2}:\d{2})?$/);
        
        if (isoMatch) {
            parsed = new Date(`${isoMatch[1]}-${isoMatch[2].padStart(2, '0')}-${isoMatch[3].padStart(2, '0')}T00:00:00Z`);
        } else {
            // Fallback to native parsing
            parsed = new Date(dateStr);
        }
    } else {
        throw new Error(`Invalid date type: ${typeof dateStr}`);
    }
    
    if (isNaN(parsed.getTime())) {
        throw new Error(`Unparseable date string: "${dateStr}"`);
    }
    
    return parsed;
}

// Helper to parse CVSS score
function parseCvssScore(value: unknown): number | null {
    if (typeof value === 'number') {
        if (value >= 0 && value <= 4) return value;
        throw new Error(`CVSS score out of range [0, 4]: ${value}`);
    }
    
    if (typeof value === 'string') {
        const parsed = parseFloat(value);
        if (!isNaN(parsed) && parsed >= 0 && parsed <= 4) return parsed;
        throw new Error(`Invalid CVSS score string: "${value}"`);
    }
    
    return null;
}

// Helper to determine severity level from CVSS
function getSeverityLevel(cvssScore: number | null): SeverityLevel {
    if (cvssScore === null) return 'UNKNOWN';
    
    const thresholds = Object.entries(SEVERITY_THRESHOLDS);
    for (const [level, threshold] of thresholds) {
        if (cvssScore >= threshold) return level as SeverityLevel;
    }
    
    return 'LOW';
}

// Interface for affected product information
interface AffectedProduct {
    vendor: string;
    product: string;
    version?: string | string[];
    platforms?: string[];
    components?: string[];
}

// Main CVE ingestion function
export async function ingestCve(
    rawRecord: unknown,
    options: IngestionOptions = {}
): Promise<IngestionResult> {
    const startTime = Date.now();
    let record: Partial<CVERecord> | null = null;
    let errors: string[] = [];
    let warnings: string[] = [];

    try {
        // Handle different input formats
        if (typeof rawRecord === 'string') {
            // Try to parse as JSON first, then plain text
            try {
                record = JSON.parse(rawRecord);
            } catch {
                // Assume it's a simple key-value format
                const pairs: Record<string, string> = {};
                rawRecord.split(/[\n,]+/).filter(Boolean).forEach(line => {
                    const eqIndex = line.indexOf('=');
                    if (eqIndex > 0) {
                        const [key, value] = [line.slice(0, eqIndex), line.slice(eqIndex + 1)];
                        pairs[key.trim()] = value.trim();
                    } else {
                        // Try to find a colon separator
                        const colonIndex = line.indexOf(':');
                        if (colonIndex > 0) {
                            const [key, value] = [line.slice(0, colonIndex), line.slice(colonIndex + 1)];
                            pairs[key.trim()] = value.trim();
                        } else {
                            // Assume first word is key
                            const parts = line.split(/\s+/);
                            if (parts.length >= 2) {
                                pairs[parts[0]] = parts.slice(1).join(' ');
                            }
                        }
                    }
                });
                
                record = Object.fromEntries(Object.entries(pairs).map(([k, v]) => [k.toLowerCase(), v]));
            }
        } else if (typeof rawRecord === 'object' && !Array.isArray(rawRecord)) {
            // Already a plain object - convert to Record type
            record = rawRecord as Partial<CVERecord>;
        } else if (Array.isArray(rawRecord)) {
            throw new Error(`Expected single CVE record, got array with ${rawRecord.length} items`);
        } else {
            throw new Error(`Unexpected input type: ${typeof rawRecord}`);
        }

        // Validate required fields
        const requiredFields = ['cveId', 'publishedDate'];
        for (const field of requiredFields) {
            if (!record[field]) {
                errors.push(`Missing required field: "${field}"`);
            }
        }

        if (errors.length > 0) {
            return {
                success: false,
                record: null,
                errors,
                warnings,
                processingTimeMs: Date.now() - startTime,
            };
        }

        // Normalize and validate CVE ID
        const normalizedId = normalizeCveId(record.cveId as string);
        if (!normalizedId) {
            errors.push(`Invalid CVE ID format: "${record.cveId}"`);
            return {
                success: false,
                record: null,
                errors,
                warnings,
                processingTimeMs: Date.now() - startTime,
            };
        }

        // Validate and normalize dates
        let publishedDate: Date;
        try {
            publishedDate = parseDate(record.publishedDate as string | Date);
        } catch (err) {
            errors.push(`Invalid published date: "${record.publishedDate}"`);
            return {
                success: false,
                record: null,
                errors,
                warnings,
                processingTimeMs: Date.now() - startTime,
            };
        }

        // Validate CVSS score if present
        let cvssScore: number | null = null;
        if (record.cvss) {
            try {
                cvssScore = parseCvssScore(record.cvss);
            } catch (err) {
                warnings.push(`CVSS parsing warning: ${err instanceof Error ? err.message : 'Unknown error'}`);
            }
        }

        // Build normalized record
        const severityLevel = getSeverityLevel(cvssScore);

        record = {
            cveId: normalizedId,
            publishedDate,
            modifiedDate: parseDate(record.modifiedDate as string | Date),
            lastModified: parseDate(record.lastModified as string | Date),
            cvssScore,
            severityLevel,
            affectedProducts: (record.affectedProducts as AffectedProduct[]).map(p => ({
                vendor: p.vendor || '',
                product: p.product || '',
                version: Array.isArray(p.version) ? p.version : [p.version],
                platforms: p.platforms || [],
                components: p.components || [],
            })),
            patchNotes: record.patchNotes as string | undefined,
            source: record.source as string | undefined,
        };

        // Check for duplicates (simple in-memory check - would need storage in production)
        const seenCves = new Set<string>();
        if (seenCves.has(normalizedId)) {
            warnings.push(`Duplicate CVE ID detected: "${normalizedId}"`);
        } else {
            seenCves.add(normalizedId);
        }

    } catch (error) {
        return {
            success: false,
            record: null,
            errors: [error instanceof Error ? error.message : 'Unknown ingestion error'],
            warnings,
            processingTimeMs: Date.now() - startTime,
        };
    }

    return {
        success: true,
        record: record as CVERecord,
        errors,
        warnings,
        processingTimeMs: Date.now() - startTime,
    };
}

// Batch ingestion for multiple records
export async function ingestCveBatch(
    rawRecords: unknown[],
    options: IngestionOptions = {}
): Promise<IngestionResult[]> {
    const results: IngestionResult[] = [];
    
    for (const [index, record] of rawRecords.entries()) {
        try {
            if (!Array.isArray(record)) {
                throw new Error(`Record ${index} is not an array`);
            }
            
            // For batch mode, assume each item in the array is a separate CVE entry
            const result = await ingestCve(record[0], options);
            result.metadata = { sourceIndex: index };
            results.push(result);
        } catch (error) {
            results.push({
                success: false,
                record: null,
                errors: [error instanceof Error ? error.message : 'Unknown batch error'],
                warnings: [],
                processingTimeMs: 0,
                metadata: { sourceIndex: index },
            });
        }
    }
    
    return results;
}

// Deduplicate CVE records by ID
export function deduplicateCves(
    records: IngestionResult[],
    options: DedupOptions = {}
): IngestionResult[] {
    const seen = new Map<string, number>(); // cveId -> first index
    const keepIndices: number[] = [];
    
    for (const [index, result] of records.entries()) {
        if (!result.success || !result.record) continue;
        
        const normalizedId = normalizeCveId(result.record.cveId);
        if (!normalizedId) continue;
        
        if (seen.has(normalizedId)) {
            // Keep the first occurrence, merge metadata from subsequent ones
            seen.get(normalizedId)!.push(index);
        } else {
            seen.set(normalizedId, [index]);
            keepIndices.push(index);
        }
    }
    
    return records.filter((_, index) => keepIndices.includes(index));
}

// Merge duplicate CVE entries (keep most complete data)
export function mergeDuplicateCves(
    results: IngestionResult[],
    options: DedupOptions = {}
): IngestionResult[] {
    const grouped: Map<string, number[]> = new Map(); // cveId -> [index1, index2, ...]
    
    for (const result of results) {
        if (!result.success || !result.record) continue;
        
        const normalizedId = normalizeCveId(result.record.cveId);
        if (!normalizedId) continue;
        
        if (!grouped.has(normalizedId)) {
            grouped.set(normalizedId, []);
        }
        grouped.get(normalizedId)!.push(results.indexOf(result));
    }
    
    const merged: IngestionResult[] = [];
    
    for (const [cveId, indices] of grouped.entries()) {
        if (indices.length === 1) {
            // Single entry - just add it back
            merged.push(results[indices[0]]);
        } else {
            // Multiple entries - merge them intelligently
            const primary = results[indices[0]];
            
            // Start with primary record
            let mergedRecord: Partial<CVERecord> = { ...primary.record };
            
            // Merge additional fields from duplicates
            for (const index of indices.slice(1)) {
                const secondary = results[index];
                
                if (!secondary.record) continue;
                
                // Merge affected products
                if (secondary.record.affectedProducts && 
                    primary.record.affectedProducts) {
                    const existingVendors = new Set(
                        primary.record.affectedProducts.map(p => p.vendor).filter(Boolean)
                    );
                    
                    for (const product of secondary.record.affectedProducts) {
                        if (!existingVendors.has(product.vendor)) {
                            mergedRecord.affectedProducts!.push({
                                vendor: product.vendor,
                                product: product.product,
                                version: product.version,
                                platforms: product.platforms,
                                components: product.components,
                            });
                            existingVendors.add(product.vendor);
                        } else if (product.product && !primary.record.affectedProducts.find(
                            p => p.vendor === product.vendor && 
                                   p.product.toLowerCase() === product.product.toLowerCase()
                        )) {
                            mergedRecord.affectedProducts!.push({
                                vendor: product.vendor,
                                product: product.product,
                                version: product.version,
                                platforms: product.platforms,
                                components: product.components,
                            });
                        }
                    }
                }
                
                // Merge patch notes if present and different
                if (secondary.record.patchNotes && 
                    !primary.record.patchNotes) {
                    mergedRecord.patchNotes = secondary.record.patchNotes;
                } else if (primary.record.patchNotes && 
                          secondary.record.patchNotes &&
                          primary.record.patchNotes !== secondary.record.patchNotes) {
                    // Combine patch notes with separator
                    const combined = `${primary.record.patchNotes}\n\n${secondary.record.patchNotes}`;
                    mergedRecord.patchNotes = combined;
                }
                
                // Merge source information
                if (secondary.record.source && !primary.record.source) {
                    mergedRecord.source = secondary.record.source;
                } else if (primary.record.source && 
                          secondary.record.source &&
                          primary.record.source !== secondary.record.source) {
                    const combinedSources = new Set([
                        primary.record.source,
                        secondary.record.source,
                    ]);
                    mergedRecord.source = Array.from(combinedSources).join('; ');
                }
            }
            
            // Rebuild the record with merged data
            mergedRecord.cveId = cveId;
            mergedRecord.severityLevel = primary.record.severityLevel || 'UNKNOWN';
            mergedRecord.cvssScore = primary.record.cvssScore;
            
            if (mergedRecord.affectedProducts) {
                // Remove duplicates while preserving order
                const unique: AffectedProduct[] = [];
                const seenProducts = new Set<string>();
                
                for (const product of mergedRecord.affectedProducts!) {
                    const key = `${product.vendor.toLowerCase()}|${product.product.toLowerCase()}`;
                    if (!seenProducts.has(key)) {
                        unique.push(product);
                        seenProducts.add(key);
                    }
                }
                
                mergedRecord.affectedProducts = unique;
            }
            
            // Create merged result with metadata about what was combined
            const mergeMetadata: Record<string, any> = {};
            for (const index of indices) {
                if (results[index].metadata) {
                    mergeMetadata[results[index].metadata.sourceIndex] = 
                        results[index].metadata;
                }
            }
            
            merged.push({
                success: true,
                record: mergedRecord as CVERecord,
                errors: [...primary.errors],
                warnings: [...primary.warnings, ...secondary.warnings.flat()],
                processingTimeMs: primary.processingTimeMs + secondary.processingTimeMs,
                metadata: {
                    sourceIndex: indices[0],
                    mergedFrom: mergeMetadata,
                },
            });
        }
    }
    
    return merged;
}

// Options for ingestion configuration
export interface IngestionOptions {
    // Maximum number of warnings before failing (default: 10)
    maxWarnings?: number;
    
    // Whether to allow duplicate CVE IDs with warnings (default: true)
    allowDuplicates?: boolean;
    
    // Custom severity thresholds
    customThresholds?: Record<SeverityLevel, number>;
}

// Options for deduplication and merging
export interface DedupOptions {
    // Merge strategy: 'first' | 'last' | 'smart'