require 'date'
require 'json'
require 'open-uri'

module Vulntimeline
  # Constants for validation and configuration
  module CveConstants
    VALID_CVE_ID_PATTERN = /\ACVE-\d{4}-\d+\z/
    MIN_CVE_YEAR = 1980
    MAX_CVE_YEAR = 2100
    
    DEFAULT_STATUS = 'Active'
    DEFAULT_SEVERITY = 'Medium'
    
    # Common date formats to try when parsing
    DATE_FORMATS = [
      '%Y-%m-%d',
      '%Y/%m/%d',
      '%B %d, %Y',
      '%b %d, %Y',
      '%d %b %Y'
    ].freeze
  end

  # Represents a single CVE record with normalized fields
  class CveRecord
    attr_reader :cve_id, :published_date, :modified_date, 
                :status, :severity, :cvss_score,
                :description, :affected_products, :references
    
    def initialize(attributes = {})
      @cve_id = attributes[:cve_id] || attributes['cve_id']
      @published_date = parse_date(attributes[:published_date])
      @modified_date = parse_date(attributes[:modified_date])
      @status = attributes[:status] || CveConstants::DEFAULT_STATUS
      @severity = attributes[:severity] || CveConstants::DEFAULT_SEVERITY
      @cvss_score = attributes[:cvss_score].to_f rescue 0.0
      @description = attributes[:description] || ''
      @affected_products = parse_affected_products(attributes)
      @references = parse_references(attributes)
    end

    def to_h
      {
        cve_id: @cve_id,
        published_date: format_date(@published_date),
        modified_date: format_date(@modified_date),
        status: @status,
        severity: @severity,
        cvss_score: @cvss_score.round(2),
        description: truncate_string(@description, 500),
        affected_products: @affected_products.map(&:to_h),
        references: @references
      }
    end

    def to_json(*args)
      JSON.generate(to_h, *args)
    end

    private

    def parse_date(date_str)
      return nil if date_str.nil? || date_str.to_s.strip.empty?
      
      Date.parse(date_str.to_s.strip) rescue nil
    end

    def format_date(date_obj)
      date_obj ? date_obj.strftime('%Y-%m-%d') : 'Unknown'
    end

    def parse_affected_products(attributes)
      # Extract affected products from various source formats
      raw = attributes[:affected_products] || 
             attributes['affected_products'] || 
             attributes[:products] ||
             attributes['products'] ||
             ''
      
      return [] if raw.nil? || raw.to_s.strip.empty?

      if raw.is_a?(Array)
        raw.map { |p| AffectedProduct.new(p) }
      else
        # Parse from string format like "Apache 2.4, Tomcat 9"
        parse_string_products(raw)
      end
    end

    def parse_string_products(text)
      products = []
      
      text.scan(/([A-Za-z][A-Za-z0-9_\-\. ]+)(?:\s+(v\d+(?:\.\d+)*)?)/) do |match|
        name, version = match[1].strip, match[2] || 'latest'
        products << AffectedProduct.new(name: name, version: version)
      end
      
      products
    end

    def parse_references(attributes)
      raw = attributes[:references] || 
             attributes['references'] || 
             attributes[:urls] ||
             attributes['urls'] ||
             ''
      
      return [] if raw.nil? || raw.to_s.strip.empty?

      if raw.is_a?(Array)
        raw.map { |r| Reference.new(r) }
      else
        # Parse from string format like "https://nvd.nist.gov/..."
        parse_string_references(raw)
      end
    end

    def parse_string_references(text)
      urls = []
      
      text.scan(/(https?:\/\/[^\s]+)/) do |match|
        url = match[1].strip
        urls << Reference.new(url: url, source: 'External') if url.start_with?('http')
      end
      
      urls
    end

    def truncate_string(str, max_len)
      return str if str.nil? || str.length <= max_len
      "#{str[0...max_len-3]}..."
    end
  end

  # Represents an affected product with version info
  class AffectedProduct
    attr_reader :name, :version
    
    def initialize(attributes = {})
      @name = attributes[:name] || attributes['name'] || 'Unknown'
      @version = extract_version(attributes)
    end

    def to_h
      { name: @name, version: format_version(@version) }
    end

    private

    def extract_version(attrs)
      return nil if attrs.nil? || attrs.to_s.strip.empty?
      
      # Try various formats
      v = attrs[:version] || 
          attrs['version'] || 
          attrs[:ver] ||
          attrs['ver'] ||
          attrs[:v] ||
          attrs['v'] ||
          ''
      
      v.is_a?(Array) ? v.join(', ') : v
    end

    def format_version(v)
      return 'Unknown' if v.nil? || v.to_s.strip.empty?
      v.to_s.strip
    end
  end

  # Represents a reference URL with metadata
  class Reference
    attr_reader :url, :source
    
    def initialize(attributes = {})
      @url = attributes[:url] || attributes['url'] || ''
      @source = attributes[:source] || 'Internal'
    end

    def to_h
      { url: @url, source: @source }
    end
  end

  # Main ingestion engine - handles parsing, validation, and deduplication
  module CveIngestion
    class << self
      include CveConstants
      
      # Process a single CVE record from any source format
      def ingest(record_hash)
        normalized = normalize_record(record_hash)
        
        return nil unless validate_normalized(normalized)
        
        # Check for duplicates (simple string-based deduplication)
        dup_key = "#{normalized.cve_id}_#{normalized.published_date}"
        if DUPLICATES.key?(dup_key)
          existing = DUPLICATES[dup_key]
          if normalized.modified_date > existing.modified_date
            DUPLICATES[dup_key] = normalized
          end
          return nil # Return nil to indicate duplicate found
        else
          DUPLICATES[dup_key] = normalized
        end
        
        normalized
      rescue => e
        warn "Error ingesting record: #{e.message}"
        nil
      end

      def ingest_batch(records)
        results = []
        
        records.each do |record|
          next unless record.is_a?(Hash) || record.respond_to?(:to_h)
          
          normalized = ingest(record.to_h)
          results << normalized if normalized
        end
        
        {
          total: records.size,
          ingested: results.size,
          duplicates: DUPLICATES.size - results.uniq(&:cve_id).size
        }
      end

      def from_nvd_json(json_string)
        begin
          data = JSON.parse(json_string)
          
          # Handle different NVD response structures
          records = extract_records(data)
          
          {
            source: 'NVD',
            timestamp: Time.now,
            records: ingest_batch(records),
            raw_data_size: json_string.bytesize
          }
        rescue JSON::ParserError => e
          warn "JSON parse error: #{e.message}"
          nil
        end
      end

      def from_nvd_file(filepath)
        content = File.read(filepath)
        from_nvd_json(content)
      end

      private

      # Normalize a raw record to standard format
      def normalize_record(raw)
        CveRecord.new(merge_default_values(raw))
      end

      # Merge default values with provided data
      def merge_default_values(raw)
        defaults = {
          status: DEFAULT_STATUS,
          severity: DEFAULT_SEVERITY,
          cvss_score: 5.0,
          description: 'No description available'
        }
        
        raw.merge(defaults).transform_keys do |key|
          key.to_s.gsub(/(\A|\A_)/, '').downcase
        end
      end

      # Validate the normalized record
      def validate_normalized(record)
        return false unless record.cve_id && !record.cve_id.to_s.strip.empty?
        
        if !CveConstants::VALID_CVE_ID_PATTERN.match?(record.cve_id.to_s)
          warn "Invalid CVE ID format: #{record.cve_id}"
          return false
        end
        
        year = extract_year(record.cve_id)
        return false unless year && year >= MIN_CVE_YEAR && year <= MAX_CVE_YEAR
        
        true
      rescue => e
        warn "Validation error: #{e.message}"
        false
      end

      def extract_year(cve_id)
        match = cve_id.to_s.match(/(\d{4})/)
        match ? match[1].to_i : nil
      end

      # Extract CVE records from various NVD response formats
      def extract_records(data)
        case data.class.name
        when 'Hash'
          if data.key?('vulnerabilities') && data['vulnerabilities'].is_a?(Array)
            data['vulnerabilities']
          elsif data.key?('CVE_Items') && data['CVE_Items'].is_a?(Array)
            data['CVE_Items']
          else
            # Try to find any array of records
            data.values.find { |v| v.is_a?(Array) }.compact.flatten(1).select do |item|
              item.is_a?(Hash) && 
                (item.key?('cve') || item.key?('CVE'))
            end.compact
          end
        when 'Array'
          data.select { |d| d.is_a?(Hash) }
        else
          []
        end
      end

      # Singleton for tracking duplicates across the session
      def DUPLICATES
        @DUPLICATES ||= {}
      end
      
      def self.DUPLICATES
        CveIngestion::DUPLICATES
      end
    end
  end

  # Demo and entry point - shows how to use the ingestion system
  if __FILE__ == $0
    puts "=== Vulntimeline CVE Ingestion Demo ==="
    
    # Sample NVD JSON response (truncated for demo)
    sample_nvd_json = {
      'vulnerabilities' => [
        {
          'cve' => {
            'CVE_data_meta' => {
              'ID' => '2024-1234',
              'State' => 'Active',
              'Date' => '2024-01-15'
            },
            'data_type' => 'Text',
            'description_data' => {
              'description' => [
                {'value' => 'Buffer overflow in Apache HTTP Server'}
              ]
            },
            'affects' => [
              {
                'vendor' => 'Apache Software Foundation',
                'product' => 'Apache HTTP Server',
                'versions' => [
                  {'version' => '2.4.50 - 2.4.51'}
                ]
              }
            ],
            'metrics' => {
              'cvss_data' => {
                'v3_1' => {
                  'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
                  'version' => 3,
                  'vectorVersion' => '3.1',
                  'score' => 9.8
                }
              }
            },
            'references' => [
              {'url' => 'https://nvd.nist.gov/vuln/detail/CVE-2024-1234'}
            ]
          }
        },
        {
          'cve' => {
            'CVE_data_meta' => {
              'ID' => '2024-5678',
              'State' => 'Active',
              'Date' => '2024-01-16'
            },
            'data_type' => 'Text',
            'description_data' => {
              'description' => [
                {'value' => 'SQL injection in WordPress plugin'}
              ]
            },
            'affects' => [
              {
                'vendor' => 'Automattic',
                'product' => 'WordPress',
                'versions' => [
                  {'version' => '6.0 - 6.1'}
                ]
              }
            ],
            'metrics' => {
              'cvss_data' => {
                'v3_1' => {
                  'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N',
                  'version' => 3,
                  'vectorVersion' => '3.1',
                  'score' => 9.0
                }
              }
            },
            'references' => [
              {'url' => 'https://wordpress.org/support/plugin/example-plugin/'}
            ]
          }
        }
      ]
    }.to_json

    # Process the sample data
    result = CveIngestion.from_nvd_json(sample_nvd_json)
    
    if result
      puts "\n--- Ingestion Results ---"
      puts "Total records processed: #{result[:total]}"
      puts "Successfully ingested:  #{result[:ingested]}"
      puts "Duplicates found:       #{result[:duplicates]}"
      
      puts "\n--- Normalized Records ---"
      result[:records].each_with_index do |record, idx|
        puts "\nRecord ##{idx + 1}:"
        puts "  CVE ID:     #{record.cve_id}"
        puts "  Published:  #{record.published_date&.strftime('%Y-%m-%d') || 'Unknown'}"
        puts "  Modified:   #{record.modified_date&.strftime('%Y-%m-%d') || 'Unknown'}"
        puts "  Status:     #{record.status}"
        puts "  Severity:   #{record.severity}"
        puts "  CVSS Score: #{record.cvss_score.round(2)}"
        puts "  Description: #{record.description[0...60]}..." if record.description.length > 60
        puts "  Products:    #{record.affected_products.map(&:name).join(', ')}" unless record.affected_products.empty?
        puts "  References:  #{record.references.map(&:url).join(', ')}" unless record.references.empty?
      end
      
      # Show duplicate tracking
      if CveIngestion::DUPLICATES.size > result[:ingested]
        puts "\n--- Duplicate Tracking ---"
        CveIngestion::DUPLICATES.each do |key, dup|
          puts "  #{key} -> Modified: #{dup.modified_date&.strftime('%Y-%m-%d')}"
        end
      end
    else
      puts "\n--- Ingestion Failed ---"
      puts "Check console for error messages."
    end

    # Demo: Batch processing with duplicates
    puts "\n=== Duplicate Handling Demo ==="
    
    batch = [
      { 'cve_id' => 'CVE-2024-9999', 'published_date' => '2024-01-01' },
      { 'cve_id' => 'CVE-2024-9999', 'published_date' => '2024-01-05' }, # Duplicate with later date
      { 'cve_id' => 'CVE-2024-8888', 'published_date' => '2024-01-03' }
    ]

    batch_results = CveIngestion.send(:CveIngestion).instance_eval do
      results = []
      batch.each do |record|
        normalized = ingest(record)
        results << normalized if normalized
      end
      { total: batch.size, ingested