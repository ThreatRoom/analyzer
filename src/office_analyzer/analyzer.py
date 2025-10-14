"""
Main OfficeAnalyzer class for comprehensive Office file analysis.
"""

import os
import hashlib
import math
from datetime import datetime
from pathlib import Path
from typing import Optional

from .models import AnalysisResult, ThreatLevel, RiskScore, FileMetadata
from .extractors import MetadataExtractor, MacroExtractor, NetworkExtractor, ObjectExtractor
from .scoring import RiskScorer
from .utils import calculate_entropy, get_file_hashes


class OfficeAnalyzer:
    """
    Main analyzer class for Office documents.

    Performs comprehensive analysis including:
    - Metadata extraction
    - Macro analysis and deobfuscation
    - Network indicator extraction
    - Risk scoring and threat classification
    - IoC identification
    """

    def __init__(self, enable_network_checks: bool = True):
        """
        Initialize the analyzer.

        Args:
            enable_network_checks: Whether to perform network-based reputation checks
        """
        self.enable_network_checks = enable_network_checks

        # Initialize extractors
        self.metadata_extractor = MetadataExtractor()
        self.macro_extractor = MacroExtractor()
        self.network_extractor = NetworkExtractor(enable_network_checks)
        self.object_extractor = ObjectExtractor()

        # Initialize risk scorer
        self.risk_scorer = RiskScorer()

    def analyze_file(self, file_path: str) -> AnalysisResult:
        """
        Perform comprehensive analysis of an Office file.

        Args:
            file_path: Path to the Office file to analyze

        Returns:
            AnalysisResult containing all analysis results

        Raises:
            FileNotFoundError: If the file doesn't exist
            ValueError: If the file format is not supported
        """
        file_path = Path(file_path).resolve()

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        if not self._is_supported_format(file_path):
            raise ValueError(f"Unsupported file format: {file_path.suffix}")

        # Get basic file information
        file_size = file_path.stat().st_size
        file_hash_sha256, file_hash_md5 = get_file_hashes(str(file_path))

        # Calculate entropy
        document_entropy = calculate_entropy(str(file_path))

        # Initialize result
        result = AnalysisResult(
            file_path=str(file_path),
            file_size=file_size,
            file_hash_sha256=file_hash_sha256,
            file_hash_md5=file_hash_md5,
            analysis_timestamp=datetime.now(),
            threat_level=ThreatLevel.NONE,
            risk_score=RiskScore(score=0),
            classification="Unknown",
            document_entropy=document_entropy,
            metadata=FileMetadata(),
            network_indicators=self.network_extractor.get_empty_indicators(),
        )

        try:
            # Extract metadata
            result.metadata = self.metadata_extractor.extract(str(file_path))

            # Extract macros
            result.macros = self.macro_extractor.extract(str(file_path))
            result.auto_execution = any(macro.auto_execution for macro in result.macros)

            # Extract network indicators
            result.network_indicators = self.network_extractor.extract(str(file_path))

            # Extract embedded objects
            result.embedded_objects = self.object_extractor.extract(str(file_path))

            # Extract additional elements
            result.dde_links = self.object_extractor.extract_dde_links(str(file_path))
            result.form_controls = self.object_extractor.extract_form_controls(str(file_path))
            result.hidden_content = self.object_extractor.extract_hidden_content(str(file_path))
            result.external_references = self.object_extractor.extract_external_references(str(file_path))

            # Perform risk scoring
            risk_result = self.risk_scorer.calculate_risk(result)
            result.risk_score = risk_result.risk_score
            result.threat_level = risk_result.threat_level
            result.classification = risk_result.classification
            result.indicators_of_compromise = risk_result.iocs

        except Exception as e:
            result.errors.append(f"Analysis error: {str(e)}")
            result.threat_level = ThreatLevel.MEDIUM
            result.risk_score = RiskScore(score=50, factors=["Analysis failed"])
            result.classification = "Analysis Failed - Treat with Caution"

        return result

    def _is_supported_format(self, file_path: Path) -> bool:
        """
        Check if the file format is supported.

        Args:
            file_path: Path to the file

        Returns:
            True if format is supported, False otherwise
        """
        supported_extensions = {
            ".docx",
            ".docm",
            ".dotx",
            ".dotm",  # Word
            ".xlsx",
            ".xlsm",
            ".xltx",
            ".xltm",  # Excel
            ".pptx",
            ".pptm",
            ".potx",
            ".potm",  # PowerPoint
            ".doc",
            ".dot",  # Legacy Word
            ".xls",
            ".xlt",  # Legacy Excel
            ".ppt",
            ".pot",  # Legacy PowerPoint
        }

        return file_path.suffix.lower() in supported_extensions

    def get_supported_formats(self) -> list:
        """
        Get list of supported file formats.

        Returns:
            List of supported file extensions
        """
        return [
            ".docx",
            ".docm",
            ".dotx",
            ".dotm",  # Word
            ".xlsx",
            ".xlsm",
            ".xltx",
            ".xltm",  # Excel
            ".pptx",
            ".pptm",
            ".potx",
            ".potm",  # PowerPoint
            ".doc",
            ".dot",  # Legacy Word
            ".xls",
            ".xlt",  # Legacy Excel
            ".ppt",
            ".pot",  # Legacy PowerPoint
        ]
