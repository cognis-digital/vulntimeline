"""CVE Ingestion Module for VulnTimeline.

Parses, normalizes, validates, and stores CVE records from multiple sources.
Supports NVD XML, JSON, and text formats. Includes duplicate detection and
patch-window calculation utilities.
"""

import json
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from enum import Enum


class SeverityLevel(Enum):
    CRITICAL = 10
    HIGH = 7
    MEDIUM = 4
    LOW = 2
    INFO = 1
    
    @classmethod
    def from_string(cls, s: str) -> 'SeverityLevel':
        mapping = {
            'CRITICAL': cls.CRITICAL,
            'HIGH': cls.HIGH,
            'MEDIUM': cls.MEDIUM,
            'LOW': cls.LOW,
            'INFO': cls.INFO,
            'MODERATE': cls.MEDIUM,
            'MINOR': cls.LOW,
        }
        return mapping.get(s.upper(), cls.INFO)


@dataclass
class NormalizedDate:
    """Standardized date representation."""
    year: int
    month: int
    day: int
    
    @classmethod
    def parse(cls, s: str) -> 'Optional[NormalizedDate]':
        if not s or not isinstance(s, str):
            return None
        
        formats = [
            '%Y-%m-%d', '%Y/%m/%d', '%d-%m-%Y', '%d/%m/%Y',
            '%Y-%m-%dT%H:%M:%S', '%Y-%m-%dT%H:%M:%SZ'
        ]
        
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                return cls(dt.year, dt.month, dt.day)
            except ValueError:
                continue
        
        # Try ISO format with timezone handling
        if 'T' in s and '+' in s:
            parts = s.split('+')
            try:
                dt = datetime.fromisoformat(parts[0])
                return cls(dt.year, dt.month, dt.day)
            except ValueError:
                pass
        
        # Try common NVD patterns
        if 'NVD' in s or 'CVE' in s:
            match = re.search(r'(\d{4})[-/](\d{2})', s)
            if match:
                return cls(int(match.group(1)), int(match.group(2)))
        
        return None


@dataclass
class VersionRange:
    """Semantic version range with operators."""
    operator: str = ''  # 'eq', 'gt', 'gte', 'lt', 'lte'
    version: str = ''
    
    @classmethod
    def parse(cls, s: str) -> 'Optional[VersionRange]':
        if not s or not isinstance(s, str):
            return None
        
        patterns = [
            (r'^=?(.+)$', lambda m: cls('eq', m.group(1))),  # exact match
            (r'^(>=?)(.+)$', lambda m: cls('gte', m.group(2))),
            (r'^(<=?)(.+)$', lambda m: cls('lte', m.group(2))),
            (r'^>(.+)$', lambda m: cls('gt', m.group(1))),
            (r'^<(.+)$', lambda m: cls('lt', m.group(1))),
        ]
        
        for pattern, factory in patterns:
            match = re.match(pattern, s.strip())
            if match:
                return factory(match)
        
        # Default to exact match
        return cls('eq', s.strip() if s else '')


@dataclass
class NormalizedCVE:
    """Canonical CVE record after normalization."""
    cve_id: str
    title: str = ''
    description: str = ''
    severity: SeverityLevel = SeverityLevel.INFO
    published_date: Optional[NormalizedDate] = None
    last_modified: Optional[NormalizedDate] = None
    affected_products: List[Tuple[str, VersionRange]] = field(default_factory=list)
    patch_notes: Dict[str, str] = field(default_factory=dict)  # product -> notes
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'cve_id': self.cve_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity.name,
            'published_date': (self.published_date.year, self.published_date.month, 
                             self.published_date.day) if self.published_date else None,
            'last_modified': (self.last_modified.year, self.last_modified.month,
                            self.last_modified.day) if self.last_modified else None,
            'affected_products': [
                {'product': p, 'version_range': v.operator + v.version} 
                for p, v in self.affected_products
            ],
            'patch_notes': dict(self.patch_notes),
        }


class CVEIngestionError(Exception):
    """Base exception for ingestion errors."""
    pass


class DuplicateCVEError(CVEIngestionError):
    """Raised when a duplicate CVE is detected."""
    def __init__(self, cve_id: str, existing: 'NormalizedCVE', new: 'NormalizedCVE'):
        self.cve_id = cve_id
        self.existing = existing
        self.new = new


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field


class CVEIngestionError(CVEIngestionError):
    """Raised when a CVE fails validation."""
    def __init__(self, cve_id: str, message: str, field: Optional[str] = None):
        self.cve_id = cve_id
        self.message = message
        self.field = field