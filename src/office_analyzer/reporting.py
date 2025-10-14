"""
Comprehensive reporting module for Office file analysis results.
"""

from datetime import datetime
import json

from .models import AnalysisResult


class ReportGenerator:
    """Generates formatted reports from analysis results."""

    def __init__(self):
        """Initialize the report generator."""
        pass

    def generate_detailed_report(self, result: AnalysisResult) -> str:
        """
        Generate a detailed analysis report in the requested format.

        Args:
            result: The analysis result to report on

        Returns:
            Formatted report string
        """
        report_lines = []

        # Header
        report_lines.append("=" * 80)
        report_lines.append("OFFICE FILE ANALYSIS REPORT")
        report_lines.append("=" * 80)
        report_lines.append("")

        # File Information
        report_lines.extend(self._generate_file_info_section(result))
        report_lines.append("")

        # AI Verdict & Risk Scoring
        report_lines.extend(self._generate_verdict_section(result))
        report_lines.append("")

        # File Metadata
        report_lines.extend(self._generate_metadata_section(result))
        report_lines.append("")

        # Network Indicators
        report_lines.extend(self._generate_network_section(result))
        report_lines.append("")

        # OLE Objects Analysis
        if result.ole_objects:
            report_lines.extend(self._generate_ole_section(result))
            report_lines.append("")

        # Embedded Objects
        report_lines.extend(self._generate_objects_section(result))
        report_lines.append("")

        # VBA/VBS Macro Analysis
        if result.macros:
            report_lines.extend(self._generate_enhanced_macro_section(result))
            report_lines.append("")

        # Indicators of Compromise
        report_lines.extend(self._generate_ioc_section(result))
        report_lines.append("")

        # Footer
        report_lines.append("=" * 80)
        report_lines.append(f"Report generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)

        return "\\n".join(report_lines)

    def _generate_file_info_section(self, result: AnalysisResult) -> list:
        """Generate file information section."""
        lines = []
        lines.append("FILE INFORMATION")
        lines.append("-" * 40)
        lines.append(f"File Path: {result.file_path}")
        lines.append(f"File Size: {result.file_size:,} bytes")
        lines.append(f"SHA256: {result.file_hash_sha256}")
        lines.append(f"MD5: {result.file_hash_md5}")
        lines.append(f"Analysis Time: {result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Document Entropy: {result.document_entropy:.2f}")
        return lines

    def _generate_verdict_section(self, result: AnalysisResult) -> list:
        """Generate AI verdict and risk scoring section."""
        lines = []
        lines.append("AI VERDICT & RISK SCORING")
        lines.append("-" * 40)
        lines.append(f"Threat Level: {result.threat_level.value}")
        lines.append(f"Risk Score: {result.risk_score.score}/100")
        lines.append(f"Classification: {result.classification}")

        if result.risk_score.factors:
            lines.append("")
            lines.append("Risk Factors:")
            for i, factor in enumerate(result.risk_score.factors, 1):
                lines.append(f"  {i}. {factor}")

        return lines

    def _generate_metadata_section(self, result: AnalysisResult) -> list:
        """Generate file metadata section."""
        lines = []
        lines.append("FILE METADATA")
        lines.append("-" * 40)

        metadata = result.metadata

        lines.append(f"Document Title: {metadata.title or 'N/A'}")
        lines.append(f"Subject: {metadata.subject or 'N/A'}")
        lines.append(f"Author: {metadata.author or 'N/A'}")
        lines.append(f"Company: {metadata.company or 'N/A'}")
        lines.append(f"Manager: {metadata.manager or 'N/A'}")
        lines.append(f"Template: {metadata.template or 'N/A'}")
        lines.append(f"Last Saved By: {metadata.last_saved_by or 'N/A'}")
        lines.append(f"Document Version: {metadata.document_version or 'N/A'}")
        lines.append(f"Language: {metadata.language or 'N/A'}")
        lines.append(f"Office Version: {metadata.office_version or 'N/A'}")
        lines.append(f"Password-Protected: {'Yes' if metadata.password_protected else 'No'}")
        lines.append(f"Embedded Files: {'Yes' if metadata.embedded_files else 'No'}")

        if metadata.creation_time:
            lines.append(f"Creation Time: {metadata.creation_time.strftime('%Y-%m-%d %H:%M:%S')}")
        if metadata.modified_time:
            lines.append(f"Modified Time: {metadata.modified_time.strftime('%Y-%m-%d %H:%M:%S')}")

        return lines

    def _generate_network_section(self, result: AnalysisResult) -> list:
        """Generate network indicators section."""
        lines = []
        lines.append("EXTRACTED URL & NETWORK INDICATORS")
        lines.append("-" * 40)

        indicators = result.network_indicators

        # URLs
        if indicators.urls:
            lines.append("Extracted URLs/domains/IPs:")
            for url in indicators.urls:
                lines.append(f"  - {url}")
        else:
            lines.append("Extracted URLs/domains/IPs: None")

        lines.append("")
        lines.append(f"Use of shortened URLs: {'Yes' if indicators.shortened_urls else 'No'}")
        lines.append(f"WebDAV or SMB paths: {'Yes' if indicators.webdav_paths or indicators.smb_paths else 'No'}")

        # Redirection chains
        if indicators.redirection_chains:
            lines.append("Redirection chains:")
            for chain in indicators.redirection_chains:
                lines.append(f"  - {chain}")
        else:
            lines.append("Redirection chains: None")

        return lines

    def _generate_objects_section(self, result: AnalysisResult) -> list:
        """Generate embedded objects section."""
        lines = []
        lines.append("EMBEDDED OBJECTS")
        lines.append("-" * 40)

        # Embedded files
        if result.embedded_objects:
            lines.append("Embedded Files:")
            for obj in result.embedded_objects:
                lines.append(f"  - {obj.name} ({obj.object_type})")
                if obj.hash_sha256:
                    lines.append(f"    SHA256: {obj.hash_sha256}")
                if obj.size:
                    lines.append(f"    Size: {obj.size} bytes")
        else:
            lines.append("Embedded Files: None")

        lines.append("")

        # Macros
        if result.macros:
            lines.append("Macros:")
            for macro in result.macros:
                lines.append(f"  - {macro.name}")
                lines.append(f"    SHA256: {macro.hash_sha256}")
                if macro.entry_point:
                    lines.append("    Entry Point: Yes")
        else:
            lines.append("Macros: None")

        lines.append("")
        lines.append(f"Auto Execution: {'Yes' if result.auto_execution else 'No'}")

        # External references
        if result.external_references:
            lines.append("External References:")
            for ref in result.external_references:
                lines.append(f"  - Type: {ref.get('type', 'unknown')}")
                lines.append(f"    Target: {ref.get('target', 'N/A')}")
                lines.append(f"    Reputation: {ref.get('reputation', 'unknown')}")
        else:
            lines.append("External References: None")

        lines.append("")

        # DDE links
        if result.dde_links:
            lines.append("DDE (Dynamic Data Exchange) links:")
            for link in result.dde_links:
                lines.append(f"  - {link}")
        else:
            lines.append("DDE (Dynamic Data Exchange) links: None")

        # Form controls
        if result.form_controls:
            lines.append("Form controls:")
            for control in result.form_controls:
                lines.append(f"  - {control}")
        else:
            lines.append("Form controls: None")

        # Hidden content
        if result.hidden_content:
            lines.append("Hidden content:")
            for hidden in result.hidden_content:
                lines.append(f"  - {hidden}")
        else:
            lines.append("Hidden content: None")

        return lines

    def _generate_ole_section(self, result: AnalysisResult) -> list:
        """Generate OLE objects analysis section."""
        lines = []
        lines.append("OLE OBJECTS ANALYSIS")
        lines.append("-" * 40)
        
        if not result.ole_objects:
            lines.append("No OLE objects found.")
            return lines
            
        lines.append(f"Total OLE Objects Found: {len(result.ole_objects)}")
        lines.append("")
        
        # Group by object type
        ole_groups = {}
        for ole_obj in result.ole_objects:
            obj_type = ole_obj.object_type
            if obj_type not in ole_groups:
                ole_groups[obj_type] = []
            ole_groups[obj_type].append(ole_obj)
            
        for obj_type, objects in ole_groups.items():
            lines.append(f"{obj_type} Objects ({len(objects)}):")
            for ole_obj in objects:
                lines.append(f"  • Section: {ole_obj.section_name}")
                lines.append(f"    ID: {ole_obj.section_id}")
                lines.append(f"    Size: {ole_obj.section_size:,} bytes")
                if ole_obj.content_type:
                    lines.append(f"    Content Type: {ole_obj.content_type}")
                if ole_obj.is_macro:
                    lines.append("    ⚠️  Contains Macro Code")
                if ole_obj.is_embedded_file:
                    lines.append("    📄 Contains Embedded File")
                if ole_obj.hash_sha256:
                    lines.append(f"    SHA256: {ole_obj.hash_sha256}")
                    
                if ole_obj.suspicious_content:
                    lines.append("    🚨 Suspicious Content:")
                    for content in ole_obj.suspicious_content:
                        lines.append(f"      - {content}")
                lines.append("")
                
        return lines

    def _generate_enhanced_macro_section(self, result: AnalysisResult) -> list:
        """Generate enhanced VBA/VBS macro analysis section."""
        lines = []
        lines.append("ENHANCED VBA/VBS MACRO ANALYSIS")
        lines.append("-" * 40)

        for macro in result.macros:
            lines.append(f"Macro: {macro.name}")
            lines.append(f"Type: {macro.macro_type}")
            lines.append(f"Lines of Code: {macro.line_count}")
            lines.append(f"Obfuscation Score: {macro.obfuscation_score}/10")
            lines.append(f"Complexity Score: {macro.complexity_score}/10")
            
            # Risk indicators
            risk_level = "🔴 HIGH RISK" if macro.obfuscation_score >= 7 else \
                        "🟡 MEDIUM RISK" if macro.obfuscation_score >= 4 else \
                        "🟢 LOW RISK"
            lines.append(f"Risk Level: {risk_level}")
            lines.append("")

            # Auto-execution
            lines.append(f"Auto-execution: {'🚨 YES' if macro.auto_execution else '✅ No'}")
            if macro.auto_execution:
                lines.append("  ⚠️  This macro will execute automatically when the document is opened")
            lines.append("")

            # Suspicious APIs
            if macro.suspicious_apis:
                lines.append("🚨 Suspicious APIs Detected:")
                for api in macro.suspicious_apis:
                    lines.append(f"  - {api}")
                lines.append("")

            # Obfuscation techniques
            if macro.obfuscation_techniques:
                lines.append("🔍 Obfuscation Techniques:")
                for technique in macro.obfuscation_techniques:
                    lines.append(f"  - {technique.replace('_', ' ').title()}")
                lines.append("")

            # Suspicious strings
            if macro.suspicious_strings:
                lines.append("🚨 Suspicious Strings:")
                for string in macro.suspicious_strings[:5]:  # Limit display
                    lines.append(f"  - {string}")
                if len(macro.suspicious_strings) > 5:
                    lines.append(f"  ... and {len(macro.suspicious_strings) - 5} more")
                lines.append("")

            # Hex/Base64 strings
            if macro.hex_strings:
                lines.append(f"🔢 Hex Strings Found: {len(macro.hex_strings)}")
                for hex_str in macro.hex_strings[:3]:
                    lines.append(f"  - {hex_str}")
                if len(macro.hex_strings) > 3:
                    lines.append(f"  ... and {len(macro.hex_strings) - 3} more")
                lines.append("")
                
            if macro.base64_strings:
                lines.append(f"📝 Base64 Strings Found: {len(macro.base64_strings)}")
                for b64_str in macro.base64_strings[:3]:
                    lines.append(f"  - {b64_str[:50]}...")
                if len(macro.base64_strings) > 3:
                    lines.append(f"  ... and {len(macro.base64_strings) - 3} more")
                lines.append("")

            # Advanced techniques detected
            lines.append("🔬 Advanced Techniques Analysis:")
            critical_techniques = ['process_injection', 'privilege_escalation', 'persistence', 'lateral_movement']
            high_risk_techniques = ['dynamic_execution', 'anti_analysis', 'network_activity']
            
            for technique, detected in macro.techniques.items():
                if detected:
                    emoji = "🚨" if technique in critical_techniques else \
                           "⚠️" if technique in high_risk_techniques else "🔍"
                    technique_name = technique.replace("_", " ").title()
                    lines.append(f"  {emoji} {technique_name}: YES")
                    
            lines.append("")

            # Deobfuscated payload
            if macro.deobfuscated_payload:
                lines.append("🔓 Deobfuscated Payload:")
                lines.append(f"  {macro.deobfuscated_payload}")
                lines.append("")

            lines.append(f"SHA256: {macro.hash_sha256}")
            lines.append("=" * 60)
            lines.append("")

        return lines

    def _generate_macro_section(self, result: AnalysisResult) -> list:
        """Generate VBA/VBS macro analysis section."""
        lines = []
        lines.append("VBA/VBS MACRO EXTRACTION")
        lines.append("-" * 40)

        for macro in result.macros:
            lines.append(f"Macro: {macro.name}")
            lines.append(f"Obfuscation Score: {macro.obfuscation_score}/10")

            if macro.obfuscation_score > 5:
                obfuscation_desc = "High obfuscation detected:"
                techniques = []
                if macro.techniques.get("string_concatenation"):
                    techniques.append("String concatenation")
                if macro.techniques.get("base64_encoding"):
                    techniques.append("Base64 encoding")
                if macro.techniques.get("hex_encoding"):
                    techniques.append("Hex encoding")
                if macro.techniques.get("char_code_conversion"):
                    techniques.append("CharCode conversion")

                if techniques:
                    lines.append(f"{obfuscation_desc} {', '.join(techniques)}")

            lines.append(f"Auto-execution: {'Yes' if macro.auto_execution else 'No'}")

            if macro.auto_execution:
                lines.append("Auto-execution triggers: AutoOpen(), Document_Open(), etc.")

            if macro.suspicious_apis:
                lines.append("Suspicious APIs:")
                for api in macro.suspicious_apis:
                    lines.append(f"  - {api}")

            # Techniques detected
            lines.append("Techniques Detected:")
            for technique, detected in macro.techniques.items():
                status = "Yes" if detected else "No"
                technique_name = technique.replace("_", " ").title()
                lines.append(f"  • {technique_name}: {status}")

            if macro.deobfuscated_payload:
                lines.append("Detected payloads:")
                lines.append(f"  {macro.deobfuscated_payload}")

            lines.append("")

        return lines

    def _generate_ioc_section(self, result: AnalysisResult) -> list:
        """Generate indicators of compromise section."""
        lines = []
        lines.append("INDICATORS OF COMPROMISE (IoCs)")
        lines.append("-" * 40)

        if result.indicators_of_compromise:
            lines.append(f"SHA256: {result.file_hash_sha256}")

            # Group IoCs by type
            ioc_groups = {}
            for ioc in result.indicators_of_compromise:
                if ioc.ioc_type not in ioc_groups:
                    ioc_groups[ioc.ioc_type] = []
                ioc_groups[ioc.ioc_type].append(ioc)

            for ioc_type, iocs in ioc_groups.items():
                lines.append(f"{ioc_type.title()}s:")
                for ioc in iocs:
                    confidence_pct = int(ioc.confidence * 100)
                    lines.append(f"  - {ioc.value} (confidence: {confidence_pct}%)")
                    if ioc.description:
                        lines.append(f"    {ioc.description}")
                lines.append("")

        else:
            lines.append("No specific indicators of compromise identified.")

        return lines

    def generate_json_report(self, result: AnalysisResult) -> str:
        """
        Generate a JSON report for programmatic consumption.

        Args:
            result: The analysis result to report on

        Returns:
            JSON-formatted report string
        """
        report_data = {
            "file_info": {
                "path": result.file_path,
                "size": result.file_size,
                "sha256": result.file_hash_sha256,
                "md5": result.file_hash_md5,
                "entropy": result.document_entropy,
                "analysis_timestamp": result.analysis_timestamp.isoformat(),
            },
            "verdict": {
                "threat_level": result.threat_level.value,
                "risk_score": result.risk_score.score,
                "classification": result.classification,
                "risk_factors": result.risk_score.factors,
            },
            "metadata": {
                "title": result.metadata.title,
                "subject": result.metadata.subject,
                "author": result.metadata.author,
                "company": result.metadata.company,
                "manager": result.metadata.manager,
                "template": result.metadata.template,
                "last_saved_by": result.metadata.last_saved_by,
                "document_version": result.metadata.document_version,
                "language": result.metadata.language,
                "office_version": result.metadata.office_version,
                "password_protected": result.metadata.password_protected,
                "embedded_files": result.metadata.embedded_files,
            },
            "network_indicators": {
                "urls": result.network_indicators.urls,
                "domains": result.network_indicators.domains,
                "ips": result.network_indicators.ips,
                "shortened_urls": result.network_indicators.shortened_urls,
                "webdav_paths": result.network_indicators.webdav_paths,
                "smb_paths": result.network_indicators.smb_paths,
                "redirection_chains": result.network_indicators.redirection_chains,
            },
            "embedded_objects": [
                {
                    "type": obj.object_type,
                    "name": obj.name,
                    "size": obj.size,
                    "sha256": obj.hash_sha256,
                    "md5": obj.hash_md5,
                    "content_type": obj.content_type,
                }
                for obj in result.embedded_objects
            ],
            "macros": [
                {
                    "name": macro.name,
                    "sha256": macro.hash_sha256,
                    "auto_execution": macro.auto_execution,
                    "obfuscation_score": macro.obfuscation_score,
                    "suspicious_apis": macro.suspicious_apis,
                    "techniques": macro.techniques,
                    "deobfuscated_payload": macro.deobfuscated_payload,
                }
                for macro in result.macros
            ],
            "indicators_of_compromise": [
                {"type": ioc.ioc_type, "value": ioc.value, "description": ioc.description, "confidence": ioc.confidence}
                for ioc in result.indicators_of_compromise
            ],
            "errors": result.errors,
            "warnings": result.warnings,
        }

        return json.dumps(report_data, indent=2, default=str)

    def save_report(self, result: AnalysisResult, output_path: str, format_type: str = "text") -> None:
        """
        Save report to file.

        Args:
            result: The analysis result to report on
            output_path: Path to save the report
            format_type: Format type ("text" or "json")
        """
        if format_type.lower() == "json":
            content = self.generate_json_report(result)
        else:
            content = self.generate_detailed_report(result)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
