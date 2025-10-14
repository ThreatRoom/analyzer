"""
Comprehensive reporting module for Office file analysis results.
"""

from datetime import datetime
import json
import html

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

        # Embedded Objects
        report_lines.extend(self._generate_objects_section(result))
        report_lines.append("")

        # VBA/VBS Macro Analysis
        if result.macros:
            report_lines.extend(self._generate_macro_section(result))
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

    def generate_html_report(self, result: AnalysisResult) -> str:
        """
        Generate a comprehensive HTML report with professional styling.

        Args:
            result: The analysis result to report on

        Returns:
            HTML-formatted report string
        """
        html_content = self._get_html_template()

        # Replace placeholders with actual data
        replacements = {
            "{{TITLE}}": html.escape(f"Office File Analysis Report - {result.file_path}"),
            "{{FILE_NAME}}": html.escape(result.file_path),
            "{{ANALYSIS_DATE}}": result.analysis_timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            "{{THREAT_LEVEL}}": result.threat_level.value,
            "{{THREAT_COLOR}}": self._get_threat_color(result.threat_level.value),
            "{{RISK_SCORE}}": str(result.risk_score.score),
            "{{CLASSIFICATION}}": html.escape(result.classification),
            "{{FILE_INFO_SECTION}}": self._generate_html_file_info(result),
            "{{VERDICT_SECTION}}": self._generate_html_verdict(result),
            "{{METADATA_SECTION}}": self._generate_html_metadata(result),
            "{{NETWORK_SECTION}}": self._generate_html_network(result),
            "{{OBJECTS_SECTION}}": self._generate_html_objects(result),
            "{{MACROS_SECTION}}": self._generate_html_macros(result),
            "{{IOC_SECTION}}": self._generate_html_iocs(result),
        }

        for placeholder, value in replacements.items():
            html_content = html_content.replace(placeholder, value)

        return html_content

    def _get_html_template(self) -> str:
        """Get the HTML template with embedded CSS."""
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{TITLE}}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5rem;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }

        .header .subtitle {
            font-size: 1.1rem;
            opacity: 0.9;
        }

        .threat-banner {
            padding: 20px;
            text-align: center;
            font-size: 1.5rem;
            font-weight: bold;
            color: white;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.5);
        }

        .threat-none { background: #27ae60; }
        .threat-low { background: #f39c12; }
        .threat-medium { background: #e67e22; }
        .threat-high { background: #e74c3c; }
        .threat-critical { background: #8e44ad; }

        .content {
            padding: 30px;
        }

        .section {
            margin-bottom: 40px;
            background: #f8f9fa;
            border-radius: 8px;
            padding: 25px;
            border-left: 4px solid #3498db;
        }

        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.8rem;
            border-bottom: 2px solid #ecf0f1;
            padding-bottom: 10px;
        }

        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .info-item {
            background: white;
            padding: 15px;
            border-radius: 6px;
            border: 1px solid #e1e8ed;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .info-label {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 5px;
        }

        .info-value {
            color: #34495e;
            word-break: break-all;
        }

        .risk-score {
            display: inline-block;
            padding: 8px 16px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
            text-shadow: 1px 1px 2px rgba(0,0,0,0.3);
        }

        .score-low { background: #27ae60; }
        .score-medium { background: #f39c12; }
        .score-high { background: #e74c3c; }

        .list-item {
            background: white;
            margin: 10px 0;
            padding: 15px;
            border-radius: 6px;
            border-left: 3px solid #3498db;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .list-item h4 {
            color: #2c3e50;
            margin-bottom: 8px;
        }

        .list-item p {
            margin: 5px 0;
            color: #7f8c8d;
        }

        .techniques-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }

        .technique-item {
            padding: 8px 12px;
            border-radius: 4px;
            font-size: 0.9rem;
            text-align: center;
        }

        .technique-yes {
            background: #e74c3c;
            color: white;
        }

        .technique-no {
            background: #ecf0f1;
            color: #7f8c8d;
        }

        .url-list {
            max-height: 300px;
            overflow-y: auto;
            background: white;
            border: 1px solid #e1e8ed;
            border-radius: 6px;
            padding: 15px;
        }

        .url-item {
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 4px;
            word-break: break-all;
            font-family: monospace;
            font-size: 0.9rem;
        }

        .ioc-table {
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 6px;
            overflow: hidden;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .ioc-table th {
            background: #34495e;
            color: white;
            padding: 12px;
            text-align: left;
        }

        .ioc-table td {
            padding: 12px;
            border-bottom: 1px solid #e1e8ed;
        }

        .ioc-table tr:nth-child(even) {
            background: #f8f9fa;
        }

        .confidence-bar {
            background: #ecf0f1;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
        }

        .confidence-fill {
            height: 100%;
            background: linear-gradient(90deg, #e74c3c 0%, #f39c12 50%, #27ae60 100%);
            transition: width 0.3s ease;
        }

        .no-data {
            text-align: center;
            color: #7f8c8d;
            font-style: italic;
            padding: 20px;
        }

        .footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9rem;
        }

        @media (max-width: 768px) {
            .container {
                margin: 10px;
                border-radius: 0;
            }

            .header h1 {
                font-size: 2rem;
            }

            .content {
                padding: 20px;
            }

            .info-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Office File Analyzer</h1>
            <div class="subtitle">Comprehensive Security Analysis Report</div>
            <div class="subtitle">{{FILE_NAME}} • {{ANALYSIS_DATE}}</div>
        </div>

        <div class="threat-banner {{THREAT_COLOR}}">
            🚨 Threat Level: {{THREAT_LEVEL}} | Risk Score: {{RISK_SCORE}}/100 | Classification: {{CLASSIFICATION}}
        </div>

        <div class="content">
            {{FILE_INFO_SECTION}}
            {{VERDICT_SECTION}}
            {{METADATA_SECTION}}
            {{NETWORK_SECTION}}
            {{OBJECTS_SECTION}}
            {{MACROS_SECTION}}
            {{IOC_SECTION}}
        </div>

        <div class="footer">
            Generated by Office File Analyzer | {{ANALYSIS_DATE}} |
            <a href="https://github.com/ThreatRoom/analyzer" style="color: #3498db;">GitHub Repository</a>
        </div>
    </div>
</body>
</html>"""

    def _get_threat_color(self, threat_level: str) -> str:
        """Get CSS class for threat level color."""
        threat_colors = {
            "None": "threat-none",
            "Low": "threat-low",
            "Medium": "threat-medium",
            "High": "threat-high",
            "Critical": "threat-critical"
        }
        return threat_colors.get(threat_level, "threat-low")

    def _generate_html_file_info(self, result: AnalysisResult) -> str:
        """Generate HTML for file information section."""
        return f"""
        <div class="section">
            <h2>📁 File Information</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">File Path</div>
                    <div class="info-value">{html.escape(result.file_path)}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">File Size</div>
                    <div class="info-value">{result.file_size:,} bytes</div>
                </div>
                <div class="info-item">
                    <div class="info-label">SHA256 Hash</div>
                    <div class="info-value" style="font-family: monospace; font-size: 0.9rem;">{result.file_hash_sha256}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">MD5 Hash</div>
                    <div class="info-value" style="font-family: monospace; font-size: 0.9rem;">{result.file_hash_md5}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Document Entropy</div>
                    <div class="info-value">{result.document_entropy:.2f}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Analysis Time</div>
                    <div class="info-value">{result.analysis_timestamp.strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
            </div>
        </div>"""

    def _generate_html_verdict(self, result: AnalysisResult) -> str:
        """Generate HTML for verdict section."""
        risk_class = "score-low" if result.risk_score.score < 30 else "score-medium" if result.risk_score.score < 70 else "score-high"

        factors_html = ""
        if result.risk_score.factors:
            factors_list = "".join(f"<li>{html.escape(factor)}</li>" for factor in result.risk_score.factors)
            factors_html = f"""
            <div class="info-item">
                <div class="info-label">Risk Factors</div>
                <ul style="margin-left: 20px; color: #e74c3c;">
                    {factors_list}
                </ul>
            </div>"""

        return f"""
        <div class="section">
            <h2>🎯 AI Verdict & Risk Assessment</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Threat Level</div>
                    <div class="info-value">
                        <span class="risk-score {self._get_threat_color(result.threat_level.value)}">{result.threat_level.value}</span>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Risk Score</div>
                    <div class="info-value">
                        <span class="risk-score {risk_class}">{result.risk_score.score}/100</span>
                    </div>
                </div>
                <div class="info-item">
                    <div class="info-label">Classification</div>
                    <div class="info-value">{html.escape(result.classification)}</div>
                </div>
                {factors_html}
            </div>
        </div>"""

    def _generate_html_metadata(self, result: AnalysisResult) -> str:
        """Generate HTML for metadata section."""
        metadata = result.metadata

        creation_time = metadata.creation_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.creation_time else 'N/A'
        modified_time = metadata.modified_time.strftime('%Y-%m-%d %H:%M:%S') if metadata.modified_time else 'N/A'

        return f"""
        <div class="section">
            <h2>📋 Document Metadata</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Title</div>
                    <div class="info-value">{html.escape(metadata.title or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Subject</div>
                    <div class="info-value">{html.escape(metadata.subject or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Author</div>
                    <div class="info-value">{html.escape(metadata.author or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Company</div>
                    <div class="info-value">{html.escape(metadata.company or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Manager</div>
                    <div class="info-value">{html.escape(metadata.manager or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Last Saved By</div>
                    <div class="info-value">{html.escape(metadata.last_saved_by or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Creation Time</div>
                    <div class="info-value">{creation_time}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Modified Time</div>
                    <div class="info-value">{modified_time}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Office Version</div>
                    <div class="info-value">{html.escape(metadata.office_version or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Language</div>
                    <div class="info-value">{html.escape(metadata.language or 'N/A')}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Password Protected</div>
                    <div class="info-value">{'✅ Yes' if metadata.password_protected else '❌ No'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">Embedded Files</div>
                    <div class="info-value">{'✅ Yes' if metadata.embedded_files else '❌ No'}</div>
                </div>
            </div>
        </div>"""

    def _generate_html_network(self, result: AnalysisResult) -> str:
        """Generate HTML for network indicators section."""
        indicators = result.network_indicators

        urls_html = ""
        if indicators.urls:
            urls_list = "".join(f'<div class="url-item">{html.escape(url)}</div>' for url in indicators.urls)
            urls_html = f'<div class="url-list">{urls_list}</div>'
        else:
            urls_html = '<div class="no-data">No URLs found</div>'

        redirections_html = ""
        if indicators.redirection_chains:
            redirections_list = "".join(f'<div class="url-item">{html.escape(chain)}</div>' for chain in indicators.redirection_chains)
            redirections_html = f'<div class="url-list">{redirections_list}</div>'
        else:
            redirections_html = '<div class="no-data">No redirection chains found</div>'

        return f"""
        <div class="section">
            <h2>🌐 Network Indicators</h2>
            <div class="info-grid">
                <div class="info-item">
                    <div class="info-label">Shortened URLs</div>
                    <div class="info-value">{'⚠️ Detected' if indicators.shortened_urls else '✅ None'}</div>
                </div>
                <div class="info-item">
                    <div class="info-label">WebDAV/SMB Paths</div>
                    <div class="info-value">{'⚠️ Detected' if indicators.webdav_paths or indicators.smb_paths else '✅ None'}</div>
                </div>
            </div>

            <h3 style="margin: 20px 0 10px 0; color: #2c3e50;">Extracted URLs/Domains/IPs</h3>
            {urls_html}

            <h3 style="margin: 20px 0 10px 0; color: #2c3e50;">Redirection Chains</h3>
            {redirections_html}
        </div>"""

    def _generate_html_objects(self, result: AnalysisResult) -> str:
        """Generate HTML for embedded objects section."""
        objects_html = ""
        if result.embedded_objects:
            for obj in result.embedded_objects:
                size_info = f"{obj.size} bytes" if obj.size else "Unknown size"
                objects_html += f"""
                <div class="list-item">
                    <h4>📎 {html.escape(obj.name)}</h4>
                    <p><strong>Type:</strong> {html.escape(obj.object_type)}</p>
                    <p><strong>Size:</strong> {size_info}</p>
                    {f'<p><strong>SHA256:</strong> <code>{obj.hash_sha256}</code></p>' if obj.hash_sha256 else ''}
                    {f'<p><strong>Content Type:</strong> {html.escape(obj.content_type)}</p>' if obj.content_type else ''}
                </div>"""
        else:
            objects_html = '<div class="no-data">No embedded objects found</div>'

        macros_html = ""
        if result.macros:
            for macro in result.macros:
                macros_html += f"""
                <div class="list-item">
                    <h4>📜 {html.escape(macro.name)}</h4>
                    <p><strong>SHA256:</strong> <code>{macro.hash_sha256}</code></p>
                    <p><strong>Auto-execution:</strong> {'⚠️ Yes' if macro.auto_execution else '✅ No'}</p>
                    <p><strong>Obfuscation Score:</strong> {macro.obfuscation_score}/10</p>
                </div>"""
        else:
            macros_html = '<div class="no-data">No macros found</div>'

        external_refs_html = ""
        if result.external_references:
            for ref in result.external_references:
                ref_type = ref.get('type', 'unknown')
                target = ref.get('target', 'N/A')
                reputation = ref.get('reputation', 'unknown')
                external_refs_html += f"""
                <div class="list-item">
                    <h4>🔗 {html.escape(ref_type.title())}</h4>
                    <p><strong>Target:</strong> {html.escape(target)}</p>
                    <p><strong>Reputation:</strong> {html.escape(reputation)}</p>
                </div>"""
        else:
            external_refs_html = '<div class="no-data">No external references found</div>'

        return f"""
        <div class="section">
            <h2>📦 Embedded Objects & Content</h2>

            <h3 style="margin: 20px 0 10px 0; color: #2c3e50;">Embedded Files</h3>
            {objects_html}

            <h3 style="margin: 20px 0 10px 0; color: #2c3e50;">Macros</h3>
            {macros_html}

            <div class="info-grid" style="margin: 20px 0;">
                <div class="info-item">
                    <div class="info-label">Auto Execution</div>
                    <div class="info-value">{'⚠️ Detected' if result.auto_execution else '✅ None'}</div>
                </div>
            </div>

            <h3 style="margin: 20px 0 10px 0; color: #2c3e50;">External References</h3>
            {external_refs_html}
        </div>"""

    def _generate_html_macros(self, result: AnalysisResult) -> str:
        """Generate HTML for macro analysis section."""
        if not result.macros:
            return """
            <div class="section">
                <h2>💻 VBA/VBS Macro Analysis</h2>
                <div class="no-data">No macros found in this document</div>
            </div>"""

        macros_html = ""
        for macro in result.macros:
            # Generate techniques grid
            techniques_html = ""
            for technique, detected in macro.techniques.items():
                technique_name = technique.replace("_", " ").title()
                css_class = "technique-yes" if detected else "technique-no"
                status = "✓" if detected else "✗"
                techniques_html += f'<div class="technique-item {css_class}">{status} {technique_name}</div>'

            # Generate suspicious APIs
            apis_html = ""
            if macro.suspicious_apis:
                apis_list = "".join(f"<li>{html.escape(api)}</li>" for api in macro.suspicious_apis)
                apis_html = f'<ul style="margin-left: 20px; color: #e74c3c;">{apis_list}</ul>'
            else:
                apis_html = '<div class="no-data">No suspicious APIs detected</div>'

            # Obfuscation level
            obfuscation_class = "score-low" if macro.obfuscation_score < 4 else "score-medium" if macro.obfuscation_score < 7 else "score-high"

            # Payload
            payload_html = ""
            if macro.deobfuscated_payload:
                payload_html = f"""
                <div class="info-item">
                    <div class="info-label">Detected Payload</div>
                    <div class="info-value" style="font-family: monospace; background: #f8f9fa; padding: 10px; border-radius: 4px;">
                        {html.escape(macro.deobfuscated_payload[:500])}
                        {'...' if len(macro.deobfuscated_payload) > 500 else ''}
                    </div>
                </div>"""

            macros_html += f"""
            <div class="list-item">
                <h3>📜 Macro: {html.escape(macro.name)}</h3>
                <div class="info-grid" style="margin: 15px 0;">
                    <div class="info-item">
                        <div class="info-label">Obfuscation Score</div>
                        <div class="info-value">
                            <span class="risk-score {obfuscation_class}">{macro.obfuscation_score}/10</span>
                        </div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Auto-execution</div>
                        <div class="info-value">{'⚠️ Yes' if macro.auto_execution else '✅ No'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">SHA256 Hash</div>
                        <div class="info-value" style="font-family: monospace; font-size: 0.9rem;">{macro.hash_sha256}</div>
                    </div>
                    {payload_html}
                </div>

                <h4 style="margin: 15px 0 10px 0; color: #2c3e50;">Obfuscation Techniques</h4>
                <div class="techniques-grid">
                    {techniques_html}
                </div>

                <h4 style="margin: 15px 0 10px 0; color: #2c3e50;">Suspicious APIs</h4>
                {apis_html}
            </div>"""

        return f"""
        <div class="section">
            <h2>💻 VBA/VBS Macro Analysis</h2>
            {macros_html}
        </div>"""

    def _generate_html_iocs(self, result: AnalysisResult) -> str:
        """Generate HTML for indicators of compromise section."""
        if not result.indicators_of_compromise:
            return """
            <div class="section">
                <h2>🚨 Indicators of Compromise (IoCs)</h2>
                <div class="no-data">No specific indicators of compromise identified</div>
            </div>"""

        # Group IoCs by type
        ioc_groups = {}
        for ioc in result.indicators_of_compromise:
            if ioc.ioc_type not in ioc_groups:
                ioc_groups[ioc.ioc_type] = []
            ioc_groups[ioc.ioc_type].append(ioc)

        table_rows = ""
        for ioc_type, iocs in ioc_groups.items():
            for ioc in iocs:
                confidence_pct = int(ioc.confidence * 100)
                table_rows += f"""
                <tr>
                    <td>{html.escape(ioc_type.title())}</td>
                    <td style="font-family: monospace; font-size: 0.9rem;">{html.escape(ioc.value)}</td>
                    <td>
                        <div class="confidence-bar">
                            <div class="confidence-fill" style="width: {confidence_pct}%"></div>
                        </div>
                        <small>{confidence_pct}%</small>
                    </td>
                    <td>{html.escape(ioc.description or 'N/A')}</td>
                </tr>"""

        return f"""
        <div class="section">
            <h2>🚨 Indicators of Compromise (IoCs)</h2>
            <div class="info-item" style="margin-bottom: 20px;">
                <div class="info-label">File SHA256</div>
                <div class="info-value" style="font-family: monospace; font-size: 0.9rem;">{result.file_hash_sha256}</div>
            </div>

            <table class="ioc-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Value</th>
                        <th>Confidence</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows}
                </tbody>
            </table>
        </div>"""

    def save_html_report(self, result: AnalysisResult, output_path: str) -> None:
        """
        Save HTML report to file.

        Args:
            result: The analysis result to report on
            output_path: Path to save the HTML report
        """
        html_content = self.generate_html_report(result)

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
