#!/usr/bin/env python3
"""
Office File Analyzer - Main CLI Interface

A comprehensive tool for analyzing Microsoft Office documents to detect
malicious content, extract metadata, analyze macros, and identify security threats.
"""

import sys
import argparse
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from office_analyzer import OfficeAnalyzer
from office_analyzer.reporting import ReportGenerator


def main():
    """Main entry point for the Office File Analyzer."""
    parser = argparse.ArgumentParser(
        description="Analyze Microsoft Office documents for malicious content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s document.docx
  %(prog)s suspicious.xlsm --output-format json
  %(prog)s presentation.pptx --output report.txt
  %(prog)s --help

Supported formats:
  Word: .docx, .docm, .dotx, .dotm, .doc, .dot
  Excel: .xlsx, .xlsm, .xltx, .xltm, .xls, .xlt
  PowerPoint: .pptx, .pptm, .potx, .potm, .ppt, .pot
        """,
    )

    parser.add_argument("file_path", help="Path to the Office file to analyze")

    parser.add_argument("--output", "-o", help="Output file path for the report (default: print to stdout)")

    parser.add_argument(
        "--output-format",
        "-f",
        choices=["text", "json"],
        default="text",
        help="Output format for the report (default: text)",
    )

    parser.add_argument("--no-network", action="store_true", help="Disable network-based checks and reputation lookups")

    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")

    parser.add_argument("--version", action="version", version="Office File Analyzer 1.0.0")

    args = parser.parse_args()

    try:
        # Validate input file
        file_path = Path(args.file_path)
        if not file_path.exists():
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            return 1

        if args.verbose:
            print(f"Analyzing file: {file_path}")
            print("Initializing analyzer...")

        # Initialize analyzer
        enable_network = not args.no_network
        analyzer = OfficeAnalyzer(enable_network_checks=enable_network)

        # Check if file format is supported
        if not analyzer._is_supported_format(file_path):
            print(f"Error: Unsupported file format: {file_path.suffix}", file=sys.stderr)
            print("Supported formats:", file=sys.stderr)
            for fmt in analyzer.get_supported_formats():
                print(f"  {fmt}", file=sys.stderr)
            return 1

        if args.verbose:
            print("Performing analysis...")

        # Perform analysis
        result = analyzer.analyze_file(str(file_path))

        if args.verbose:
            print("Generating report...")

        # Generate report
        reporter = ReportGenerator()

        if args.output_format == "json":
            report_content = reporter.generate_json_report(result)
        else:
            report_content = reporter.generate_detailed_report(result)

        # Output report
        if args.output:
            output_path = Path(args.output)
            reporter.save_report(result, str(output_path), args.output_format)
            print(f"Report saved to: {output_path}")
        else:
            print(report_content)

        # Print warnings/errors if any
        if result.warnings:
            print("\\nWarnings:", file=sys.stderr)
            for warning in result.warnings:
                print(f"  - {warning}", file=sys.stderr)

        if result.errors:
            print("\\nErrors:", file=sys.stderr)
            for error in result.errors:
                print(f"  - {error}", file=sys.stderr)

        # Exit with appropriate code based on threat level
        if result.threat_level.value in ["High", "Critical"]:
            return 2  # High threat detected
        elif result.threat_level.value == "Medium":
            return 1  # Medium threat detected
        else:
            return 0  # Clean or low threat

    except KeyboardInterrupt:
        print("\\nAnalysis interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
