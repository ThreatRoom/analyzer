"""
Risk scoring and threat classification system.
"""

from dataclasses import dataclass
from typing import List

from .models import AnalysisResult, ThreatLevel, RiskScore, IoC


@dataclass
class RiskScoringResult:
    """Result of risk scoring analysis."""

    risk_score: RiskScore
    threat_level: ThreatLevel
    classification: str
    iocs: List[IoC]


class RiskScorer:
    """Calculates risk scores and classifies threats in Office documents."""

    def __init__(self):
        """Initialize the risk scorer."""
        pass

    def calculate_risk(self, analysis_result: AnalysisResult) -> RiskScoringResult:
        """
        Calculate comprehensive risk score for an analysis result.

        Args:
            analysis_result: The analysis result to score

        Returns:
            RiskScoringResult with calculated scores and classification
        """
        risk_factors = []
        score = 0
        iocs = []

        # OLE objects scoring (new enhanced analysis)
        ole_score, ole_factors, ole_iocs = self._score_ole_objects(analysis_result)
        score += ole_score
        risk_factors.extend(ole_factors)
        iocs.extend(ole_iocs)

        # Enhanced macro-based scoring
        macro_score, macro_factors, macro_iocs = self._score_enhanced_macros(analysis_result)
        score += macro_score
        risk_factors.extend(macro_factors)
        iocs.extend(macro_iocs)

        # Network indicators scoring
        network_score, network_factors, network_iocs = self._score_network_indicators(analysis_result)
        score += network_score
        risk_factors.extend(network_factors)
        iocs.extend(network_iocs)

        # Embedded objects scoring
        objects_score, objects_factors, objects_iocs = self._score_embedded_objects(analysis_result)
        score += objects_score
        risk_factors.extend(objects_factors)
        iocs.extend(objects_iocs)

        # Document properties scoring
        properties_score, properties_factors = self._score_document_properties(analysis_result)
        score += properties_score
        risk_factors.extend(properties_factors)

        # Entropy scoring
        entropy_score, entropy_factors = self._score_entropy(analysis_result)
        score += entropy_score
        risk_factors.extend(entropy_factors)

        # External references scoring
        external_score, external_factors = self._score_external_references(analysis_result)
        score += external_score
        risk_factors.extend(external_factors)

        # Cap the score at 100
        final_score = min(score, 100)

        # Determine threat level and classification
        threat_level = self._determine_threat_level(final_score)
        classification = self._classify_threat(analysis_result, final_score)

        return RiskScoringResult(
            risk_score=RiskScore(score=final_score, factors=risk_factors),
            threat_level=threat_level,
            classification=classification,
            iocs=iocs,
        )

    def _score_ole_objects(self, result: AnalysisResult) -> tuple:
        """Score OLE objects for security risks."""
        score = 0
        factors = []
        iocs = []

        if not result.ole_objects:
            return score, factors, iocs

        # Basic OLE object presence
        score += min(len(result.ole_objects) * 2, 10)
        factors.append(f"{len(result.ole_objects)} OLE objects found")

        for ole_obj in result.ole_objects:
            # Macro-containing OLE objects are high risk
            if ole_obj.is_macro:
                score += 15
                factors.append(f"OLE object contains macro: {ole_obj.section_name}")
                iocs.append(
                    IoC(
                        ioc_type="ole_macro",
                        value=ole_obj.hash_sha256 or ole_obj.section_id,
                        description=f"OLE object with macro code: {ole_obj.section_name}",
                        confidence=0.9,
                    )
                )

            # Embedded files in OLE objects
            if ole_obj.is_embedded_file:
                score += 10
                factors.append(f"Embedded file in OLE: {ole_obj.section_name}")
                if ole_obj.hash_sha256:
                    iocs.append(
                        IoC(
                            ioc_type="embedded_file",
                            value=ole_obj.hash_sha256,
                            description=f"Embedded file hash: {ole_obj.section_name}",
                            confidence=0.8,
                        )
                    )

            # Suspicious content in OLE objects
            if ole_obj.suspicious_content:
                susp_score = min(len(ole_obj.suspicious_content) * 3, 15)
                score += susp_score
                factors.append(f"Suspicious content in OLE {ole_obj.section_name}: {len(ole_obj.suspicious_content)} indicators")

                for content in ole_obj.suspicious_content:
                    if "Suspicious API" in content:
                        iocs.append(
                            IoC(
                                ioc_type="suspicious_api",
                                value=content,
                                description=f"Suspicious API in OLE object {ole_obj.section_name}",
                                confidence=0.7,
                            )
                        )

            # Large OLE objects can be suspicious
            if ole_obj.section_size > 100000:  # > 100KB
                score += 5
                factors.append(f"Large OLE object: {ole_obj.section_name} ({ole_obj.section_size:,} bytes)")

        return score, factors, iocs

    def _score_enhanced_macros(self, result: AnalysisResult) -> tuple:
        """Score enhanced macro analysis results."""
        score = 0
        factors = []
        iocs = []

        if not result.macros:
            return score, factors, iocs

        for macro in result.macros:
            # Auto-execution macros are high risk
            if macro.auto_execution:
                score += 30
                factors.append(f"Auto-executing macro: {macro.name}")
                iocs.append(
                    IoC(
                        ioc_type="macro",
                        value=macro.name,
                        description="Auto-executing VBA macro",
                        confidence=0.9,
                    )
                )

            # Enhanced obfuscation scoring
            if macro.obfuscation_score > 7:
                score += 25
                factors.append(f"Highly obfuscated macro {macro.name} (score: {macro.obfuscation_score}/10)")
            elif macro.obfuscation_score > 4:
                score += 15
                factors.append(f"Moderately obfuscated macro {macro.name} (score: {macro.obfuscation_score}/10)")

            # Complexity scoring
            if macro.complexity_score > 7:
                score += 10
                factors.append(f"Highly complex macro {macro.name} (complexity: {macro.complexity_score}/10)")

            # Suspicious APIs with enhanced scoring
            if macro.suspicious_apis:
                api_score = min(len(macro.suspicious_apis) * 3, 20)
                score += api_score
                factors.append(f"{len(macro.suspicious_apis)} suspicious APIs in {macro.name}")

                for api in macro.suspicious_apis:
                    iocs.append(
                        IoC(
                            ioc_type="api_call",
                            value=api,
                            description=f"Suspicious API call in macro {macro.name}",
                            confidence=0.8,
                        )
                    )

            # Obfuscation techniques scoring
            if macro.obfuscation_techniques:
                tech_score = min(len(macro.obfuscation_techniques) * 4, 20)
                score += tech_score
                factors.append(f"Obfuscation techniques in {macro.name}: {', '.join(macro.obfuscation_techniques[:3])}")

            # Suspicious strings
            if macro.suspicious_strings:
                susp_score = min(len(macro.suspicious_strings) * 2, 15)
                score += susp_score
                factors.append(f"{len(macro.suspicious_strings)} suspicious strings in {macro.name}")

                for susp_str in macro.suspicious_strings[:3]:  # Limit to avoid spam
                    iocs.append(
                        IoC(
                            ioc_type="suspicious_string",
                            value=susp_str[:100],  # Truncate long strings
                            description=f"Suspicious string in macro {macro.name}",
                            confidence=0.7,
                        )
                    )

            # Hex and Base64 strings
            if macro.hex_strings:
                score += min(len(macro.hex_strings) * 2, 10)
                factors.append(f"{len(macro.hex_strings)} hex strings in {macro.name}")

            if macro.base64_strings:
                score += min(len(macro.base64_strings) * 3, 15)
                factors.append(f"{len(macro.base64_strings)} base64 strings in {macro.name}")

            # Advanced techniques scoring
            critical_techniques = ['process_injection', 'privilege_escalation', 'persistence', 'lateral_movement']
            high_risk_techniques = ['dynamic_execution', 'anti_analysis', 'network_activity']
            
            for technique, detected in macro.techniques.items():
                if detected:
                    if technique in critical_techniques:
                        score += 20
                        factors.append(f"Critical technique detected in {macro.name}: {technique.replace('_', ' ')}")
                    elif technique in high_risk_techniques:
                        score += 15
                        factors.append(f"High-risk technique detected in {macro.name}: {technique.replace('_', ' ')}")
                    else:
                        score += 5

            # Deobfuscated payload analysis
            if macro.deobfuscated_payload:
                payload_lower = macro.deobfuscated_payload.lower()
                
                if "powershell" in payload_lower:
                    score += 25
                    factors.append(f"PowerShell execution detected in {macro.name}")
                    iocs.append(
                        IoC(
                            ioc_type="powershell",
                            value=macro.deobfuscated_payload[:200],
                            description=f"PowerShell command in macro {macro.name}",
                            confidence=0.9,
                        )
                    )
                
                if any(cmd in payload_lower for cmd in ["cmd.exe", "rundll32", "regsvr32", "mshta"]):
                    score += 20
                    factors.append(f"Command execution detected in {macro.name}")
                
                if "http" in payload_lower:
                    score += 15
                    factors.append(f"Network communication detected in {macro.name}")

        return score, factors, iocs

    def _score_macros(self, result: AnalysisResult) -> tuple:
        """Score macro-related risks."""
        score = 0
        factors = []
        iocs = []

        if not result.macros:
            return score, factors, iocs

        for macro in result.macros:
            # Auto-execution macros are high risk
            if macro.auto_execution:
                score += 30
                factors.append("Auto-executing macro detected")
                iocs.append(
                    IoC(ioc_type="macro", value=macro.name, description="Auto-executing VBA macro", confidence=0.9)
                )

            # Suspicious APIs
            if macro.suspicious_apis:
                api_score = min(len(macro.suspicious_apis) * 5, 25)
                score += api_score
                factors.append(f"Suspicious APIs: {', '.join(macro.suspicious_apis[:3])}")

                for api in macro.suspicious_apis:
                    iocs.append(
                        IoC(
                            ioc_type="api_call",
                            value=api,
                            description=f"Suspicious API call in macro {macro.name}",
                            confidence=0.8,
                        )
                    )

            # Obfuscation scoring
            if macro.obfuscation_score > 5:
                obfuscation_score = min(macro.obfuscation_score * 3, 20)
                score += obfuscation_score
                factors.append(f"Highly obfuscated macro (score: {macro.obfuscation_score}/10)")

            # Specific techniques
            if macro.techniques.get("base64_encoding"):
                score += 10
                factors.append("Base64 encoding detected in macro")

            if macro.techniques.get("network_activity"):
                score += 15
                factors.append("Network activity detected in macro")

            if macro.techniques.get("file_operations"):
                score += 10
                factors.append("File operations detected in macro")

            # Deobfuscated payload
            if macro.deobfuscated_payload:
                if "powershell" in macro.deobfuscated_payload.lower():
                    score += 20
                    factors.append("PowerShell execution detected")
                    iocs.append(
                        IoC(
                            ioc_type="powershell",
                            value=macro.deobfuscated_payload[:100],
                            description="PowerShell command in macro",
                            confidence=0.9,
                        )
                    )

        return score, factors, iocs

    def _score_network_indicators(self, result: AnalysisResult) -> tuple:
        """Score network-related risks."""
        score = 0
        factors = []
        iocs = []

        indicators = result.network_indicators

        # URLs
        if indicators.urls:
            url_score = min(len(indicators.urls) * 5, 20)
            score += url_score
            factors.append(f"{len(indicators.urls)} URL(s) found")

            for url in indicators.urls:
                iocs.append(IoC(ioc_type="url", value=url, description="URL found in document", confidence=0.7))

        # IP addresses
        if indicators.ips:
            ip_score = min(len(indicators.ips) * 8, 25)
            score += ip_score
            factors.append(f"{len(indicators.ips)} IP address(es) found")

            for ip in indicators.ips:
                iocs.append(IoC(ioc_type="ip", value=ip, description="IP address found in document", confidence=0.8))

        # Shortened URLs
        if indicators.shortened_urls:
            score += 15
            factors.append("Shortened URLs detected")

        # WebDAV/SMB paths
        if indicators.webdav_paths:
            score += 20
            factors.append("WebDAV paths detected")

        if indicators.smb_paths:
            score += 15
            factors.append("SMB/UNC paths detected")

        # Redirection chains
        if indicators.redirection_chains:
            score += 10
            factors.append("URL redirection chains detected")

        return score, factors, iocs

    def _score_embedded_objects(self, result: AnalysisResult) -> tuple:
        """Score embedded objects risks."""
        score = 0
        factors = []
        iocs = []

        if result.embedded_objects:
            object_score = min(len(result.embedded_objects) * 5, 15)
            score += object_score
            factors.append(f"{len(result.embedded_objects)} embedded object(s)")

            for obj in result.embedded_objects:
                if obj.hash_sha256:
                    iocs.append(
                        IoC(
                            ioc_type="file_hash",
                            value=obj.hash_sha256,
                            description=f"Embedded object: {obj.name}",
                            confidence=0.6,
                        )
                    )

        # DDE links
        if result.dde_links:
            score += 25
            factors.append("DDE (Dynamic Data Exchange) links detected")

        # Form controls
        if result.form_controls:
            score += 10
            factors.append("Form controls detected")

        # Hidden content
        if result.hidden_content:
            score += 15
            factors.append("Hidden content detected")

        return score, factors, iocs

    def _score_document_properties(self, result: AnalysisResult) -> tuple:
        """Score document properties risks."""
        score = 0
        factors = []

        metadata = result.metadata

        # Password protection
        if metadata.password_protected:
            score += 10
            factors.append("Password protected document")

        # Suspicious author/company patterns
        if metadata.author:
            suspicious_authors = ["user", "admin", "test", ""]
            if metadata.author.lower() in suspicious_authors:
                score += 5
                factors.append("Suspicious author name")

        # No metadata (could indicate tampering)
        if not any([metadata.title, metadata.author, metadata.company]):
            score += 5
            factors.append("Missing document metadata")

        return score, factors

    def _score_entropy(self, result: AnalysisResult) -> tuple:
        """Score based on document entropy."""
        score = 0
        factors = []

        entropy = result.document_entropy

        # High entropy could indicate packed/encrypted content
        if entropy > 7.5:
            score += 20
            factors.append(f"Very high entropy ({entropy:.2f}) - possible packed content")
        elif entropy > 7.0:
            score += 10
            factors.append(f"High entropy ({entropy:.2f})")
        elif entropy < 3.0:
            score += 5
            factors.append(f"Very low entropy ({entropy:.2f}) - possible template")

        return score, factors

    def _score_external_references(self, result: AnalysisResult) -> tuple:
        """Score external references."""
        score = 0
        factors = []

        if result.external_references:
            ref_score = min(len(result.external_references) * 8, 20)
            score += ref_score
            factors.append(f"{len(result.external_references)} external reference(s)")

        return score, factors

    def _determine_threat_level(self, score: int) -> ThreatLevel:
        """Determine threat level based on score."""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        elif score >= 20:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.NONE

    def _classify_threat(self, result: AnalysisResult, score: int) -> str:
        """Classify the type of threat based on analysis."""
        classifications = []

        # Macro-based classification
        if result.macros:
            if any(macro.auto_execution for macro in result.macros):
                if any("powershell" in (macro.deobfuscated_payload or "").lower() for macro in result.macros):
                    classifications.append("Macro Dropper with PowerShell")
                elif any(macro.techniques.get("network_activity") for macro in result.macros):
                    classifications.append("Macro with Network C2")
                else:
                    classifications.append("Malicious Macro")

        # Network-based classification
        if result.network_indicators.urls or result.network_indicators.ips:
            if result.network_indicators.shortened_urls:
                classifications.append("URL Redirector")
            else:
                classifications.append("Network Document")

        # DDE-based
        if result.dde_links:
            classifications.append("DDE Exploit")

        # Embedded objects
        if result.embedded_objects:
            classifications.append("Document with Embedded Objects")

        # Default classification based on score
        if not classifications:
            if score >= 60:
                return "Suspicious Document"
            elif score >= 40:
                return "Potentially Unwanted Document"
            elif score >= 20:
                return "Low Risk Document"
            else:
                return "Clean Document"

        return " + ".join(classifications[:2])  # Limit to top 2 classifications
