"""
Data models for office file analysis results.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any
from datetime import datetime


class ThreatLevel(Enum):
    """Enumeration of threat levels."""

    NONE = "None"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass
class RiskScore:
    """Risk scoring information."""

    score: int  # 0-100
    max_score: int = 100
    factors: List[str] = field(default_factory=list)


@dataclass
class FileMetadata:
    """File metadata information."""

    title: Optional[str] = None
    subject: Optional[str] = None
    author: Optional[str] = None
    company: Optional[str] = None
    manager: Optional[str] = None
    template: Optional[str] = None
    last_saved_by: Optional[str] = None
    document_version: Optional[str] = None
    language: Optional[str] = None
    office_version: Optional[str] = None
    password_protected: bool = False
    embedded_files: bool = False
    creation_time: Optional[datetime] = None
    modified_time: Optional[datetime] = None


@dataclass
class NetworkIndicator:
    """Network-related indicators found in the document."""

    urls: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    shortened_urls: bool = False
    webdav_paths: bool = False
    smb_paths: bool = False
    redirection_chains: List[str] = field(default_factory=list)


@dataclass
class EmbeddedObject:
    """Information about embedded objects."""

    object_type: str
    name: Optional[str] = None
    size: Optional[int] = None
    hash_sha256: Optional[str] = None
    hash_md5: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class OLEObjectInfo:
    """Information about OLE objects found in Office files."""

    section_id: str
    section_name: str
    section_size: int
    object_type: str
    content_type: Optional[str] = None
    is_macro: bool = False
    is_embedded_file: bool = False
    hash_sha256: Optional[str] = None
    hash_md5: Optional[str] = None
    suspicious_content: List[str] = field(default_factory=list)


@dataclass
class MacroInfo:
    """VBA/VBS macro information."""

    name: str
    content: str
    hash_sha256: str
    hash_md5: str
    macro_type: str = "VBA"  # VBA, VBScript, etc.
    entry_point: bool = False
    auto_execution: bool = False
    obfuscation_score: int = 0  # 0-10
    suspicious_apis: List[str] = field(default_factory=list)
    obfuscation_techniques: List[str] = field(default_factory=list)
    suspicious_strings: List[str] = field(default_factory=list)
    hex_strings: List[str] = field(default_factory=list)
    base64_strings: List[str] = field(default_factory=list)
    line_count: int = 0
    complexity_score: int = 0  # 0-10 for code complexity
    techniques: Dict[str, bool] = field(default_factory=dict)
    deobfuscated_payload: Optional[str] = None


@dataclass
class IoC:
    """Indicator of Compromise."""

    ioc_type: str  # "hash", "domain", "ip", "file_path", etc.
    value: str
    description: Optional[str] = None
    confidence: float = 1.0  # 0.0-1.0


@dataclass
class AnalysisResult:
    """Complete analysis result for an Office file."""

    # Basic file info
    file_path: str
    file_size: int
    file_hash_sha256: str
    file_hash_md5: str
    analysis_timestamp: datetime

    # AI Verdict & Risk Scoring
    threat_level: ThreatLevel
    risk_score: RiskScore
    classification: str
    document_entropy: float

    # File Metadata
    metadata: FileMetadata

    # Network Indicators
    network_indicators: NetworkIndicator

    # Embedded Objects and OLE Analysis
    embedded_objects: List[EmbeddedObject] = field(default_factory=list)
    ole_objects: List[OLEObjectInfo] = field(default_factory=list)
    macros: List[MacroInfo] = field(default_factory=list)
    auto_execution: bool = False
    external_references: List[Dict[str, Any]] = field(default_factory=list)
    dde_links: List[str] = field(default_factory=list)
    form_controls: List[str] = field(default_factory=list)
    hidden_content: List[str] = field(default_factory=list)

    # IoCs
    indicators_of_compromise: List[IoC] = field(default_factory=list)

    # Processing errors/warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
