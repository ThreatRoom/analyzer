"""
OfficeAnalyzer - A comprehensive Office file analysis and malware detection tool.

This package provides tools for analyzing Microsoft Office documents to detect
malicious content, extract metadata, analyze macros, and identify security threats.
"""

from .analyzer import OfficeAnalyzer
from .models import AnalysisResult, ThreatLevel, RiskScore
from .extractors import MetadataExtractor, MacroExtractor, NetworkExtractor
from .scoring import RiskScorer
from .reporting import ReportGenerator

__version__ = "1.0.0"
__author__ = "Office Analysis Tool"

__all__ = [
    "OfficeAnalyzer",
    "AnalysisResult",
    "ThreatLevel",
    "RiskScore",
    "MetadataExtractor",
    "MacroExtractor",
    "NetworkExtractor",
    "RiskScorer",
    "ReportGenerator",
]
