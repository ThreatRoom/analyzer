#!/usr/bin/env python3
"""
Basic test to verify the Office Analyzer functionality.
"""

import sys
import tempfile
import zipfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from office_analyzer import OfficeAnalyzer
from office_analyzer.reporting import ReportGenerator
from office_analyzer.extractors.ole_extractor import EnhancedOLEExtractor


def create_simple_docx():
    """Create a simple test docx file."""
    # Create a minimal docx file
    with tempfile.NamedTemporaryFile(suffix=".docx", delete=False) as tmp:
        with zipfile.ZipFile(tmp, "w") as zip_file:
            # Add minimal document.xml
            document_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
    <w:body>
        <w:p>
            <w:r>
                <w:t>Test document for analysis</w:t>
            </w:r>
        </w:p>
    </w:body>
</w:document>'''

            # Add content types
            content_types = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
    <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
    <Default Extension="xml" ContentType="application/xml"/>
    <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>'''

            # Add app properties
            app_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties">
    <Application>Microsoft Office Word</Application>
    <Company>Test Company</Company>
    <AppVersion>16.0000</AppVersion>
</Properties>'''

            # Add core properties
            core_xml = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
                   xmlns:dc="http://purl.org/dc/elements/1.1/"
                   xmlns:dcterms="http://purl.org/dc/terms/">
    <dc:title>Test Document</dc:title>
    <dc:subject>Testing</dc:subject>
    <dc:creator>Test Author</dc:creator>
    <cp:lastModifiedBy>Test User</cp:lastModifiedBy>
</cp:coreProperties>'''

            # Add main relationship
            main_rels = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
    <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
    <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>
    <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/>
</Relationships>'''

            zip_file.writestr("[Content_Types].xml", content_types)
            zip_file.writestr("_rels/.rels", main_rels)
            zip_file.writestr("word/document.xml", document_xml)
            zip_file.writestr("docProps/app.xml", app_xml)
            zip_file.writestr("docProps/core.xml", core_xml)

        return tmp.name


def test_basic_analysis():
    """Test basic analysis functionality."""
    print("Creating test document...")
    test_file = create_simple_docx()

    try:
        print(f"Testing analysis of: {test_file}")

        # Initialize analyzer
        analyzer = OfficeAnalyzer(enable_network_checks=False)

        # Perform analysis
        result = analyzer.analyze_file(test_file)

        # Basic assertions
        assert result is not None, "Analysis result should not be None"
        assert result.file_path == test_file, "File path should match"
        assert result.file_size > 0, "File size should be greater than 0"
        assert len(result.file_hash_sha256) == 64, "SHA256 hash should be 64 characters"
        assert len(result.file_hash_md5) == 32, "MD5 hash should be 32 characters"

        # Check metadata extraction
        assert result.metadata is not None, "Metadata should be extracted"
        # Note: Metadata extraction may not work perfectly with minimal test file
        print(f"   - Extracted title: {result.metadata.title}")
        print(f"   - Extracted author: {result.metadata.author}")

        # Test report generation
        reporter = ReportGenerator()
        text_report = reporter.generate_detailed_report(result)
        json_report = reporter.generate_json_report(result)

        assert len(text_report) > 100, "Text report should be substantial"
        assert '"file_info"' in json_report, "JSON report should contain file_info"
        assert '"metadata"' in json_report, "JSON report should contain metadata"

        print("✅ Basic analysis test passed!")
        print(f"   - File analyzed: {Path(test_file).name}")
        print(f"   - Threat level: {result.threat_level.value}")
        print(f"   - Risk score: {result.risk_score.score}/100")
        print(f"   - Classification: {result.classification}")
        print(f"   - Entropy: {result.document_entropy:.2f}")
        print(f"   - Metadata title: {result.metadata.title}")
        print(f"   - Metadata author: {result.metadata.author}")

        return True

    except Exception as e:
        print(f"❌ Test failed: {str(e)}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        # Clean up
        try:
            Path(test_file).unlink()
        except Exception:
            pass


def test_enhanced_ole_extraction():
    """Test enhanced OLE extraction functionality."""
    print("\nTesting enhanced OLE extraction...")
    test_file = create_simple_docx()

    try:
        # Initialize enhanced OLE extractor
        extractor = EnhancedOLEExtractor()
        
        # Test OLE object extraction
        ole_objects = extractor.extract_ole_objects(test_file)
        print(f"   - Found {len(ole_objects)} OLE objects")
        
        # Test enhanced macro extraction (should be empty for clean file)
        macros = extractor.extract_enhanced_macros(test_file)
        print(f"   - Found {len(macros)} macros")
        
        # Test with analyzer integration
        analyzer = OfficeAnalyzer(enable_network_checks=False)
        result = analyzer.analyze_file(test_file)
        
        # Verify enhanced features are present
        assert hasattr(result, 'ole_objects'), "Result should have ole_objects attribute"
        assert isinstance(result.ole_objects, list), "ole_objects should be a list"
        
        # Check for enhanced macro fields
        for macro in result.macros:
            assert hasattr(macro, 'macro_type'), "Macro should have macro_type"
            assert hasattr(macro, 'obfuscation_score'), "Macro should have obfuscation_score"
            assert hasattr(macro, 'complexity_score'), "Macro should have complexity_score"
            assert hasattr(macro, 'obfuscation_techniques'), "Macro should have obfuscation_techniques"
            assert hasattr(macro, 'suspicious_strings'), "Macro should have suspicious_strings"
            assert hasattr(macro, 'hex_strings'), "Macro should have hex_strings"
            assert hasattr(macro, 'base64_strings'), "Macro should have base64_strings"
        
        print("✅ Enhanced OLE extraction test passed!")
        return True
        
    except Exception as e:
        print(f"❌ Enhanced OLE extraction test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Clean up
        try:
            Path(test_file).unlink()
        except Exception:
            pass


def test_cli_interface():
    """Test the CLI interface."""
    print("\nTesting CLI interface...")
    test_file = create_simple_docx()

    try:
        import subprocess

        # Test help command
        result = subprocess.run([sys.executable, "analyze_office.py", "--help"], capture_output=True, text=True)
        assert result.returncode == 0, "Help command should succeed"
        assert "Analyze Microsoft Office documents" in result.stdout, "Help should contain description"

        # Test version command
        result = subprocess.run([sys.executable, "analyze_office.py", "--version"], capture_output=True, text=True)
        assert result.returncode == 0, "Version command should succeed"

        # Test actual analysis
        result = subprocess.run(
            [sys.executable, "analyze_office.py", test_file, "--no-network"], capture_output=True, text=True
        )
        assert result.returncode == 0, f"Analysis should succeed, but got return code {result.returncode}"
        assert "OFFICE FILE ANALYSIS REPORT" in result.stdout, "Output should contain report header"

        print("✅ CLI interface test passed!")
        return True

    except Exception as e:
        print(f"❌ CLI test failed: {str(e)}")
        import traceback

        traceback.print_exc()
        return False

    finally:
        # Clean up
        try:
            Path(test_file).unlink()
        except Exception:
            pass


def test_html_report():
    """Test HTML report generation."""
    print("\\nTesting HTML report generation...")
    test_file = create_simple_docx()

    try:
        import subprocess
        import os

        test_html_file = "/tmp/test_report.html"

        # Test HTML report generation via CLI
        result = subprocess.run([
            sys.executable, "analyze_office.py", test_file,
            "--html-report", test_html_file, "--no-network"
        ], capture_output=True, text=True, timeout=30)

        if result.returncode == 0 and os.path.exists(test_html_file):
            # Check if HTML file contains expected content
            with open(test_html_file, 'r', encoding='utf-8') as f:
                html_content = f.read()

            expected_elements = [
                "<!DOCTYPE html>",
                "Office File Analyzer",
                "Threat Level:",
                "Risk Score:",
                "File Information",
                "Document Metadata",
                "Network Indicators",
                "VBA/VBS Macro Analysis",
                "Indicators of Compromise"
            ]

            missing_elements = [elem for elem in expected_elements if elem not in html_content]

            if not missing_elements:
                print("✅ HTML report generation test passed!")
                print(f"   - HTML report created: {test_html_file}")
                print(f"   - File size: {os.path.getsize(test_html_file):,} bytes")
                print("   - Contains all expected sections")

                # Clean up
                os.remove(test_html_file)
                return True
            else:
                print(f"❌ HTML report test failed: Missing elements: {missing_elements}")
                return False
        else:
            print(f"❌ HTML report test failed: Return code {result.returncode}")
            if result.stderr:
                print(f"   Error: {result.stderr}")
            return False

    except Exception as e:
        print(f"❌ HTML report test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        # Clean up
        try:
            Path(test_file).unlink()
        except Exception:
            pass
        try:
            os.remove("/tmp/test_report.html")
        except Exception:
            pass


if __name__ == "__main__":
    print("Running basic functionality tests...")
    print("=" * 50)

    success = True

    # Test basic analysis
    if not test_basic_analysis():
        success = False

    # Test enhanced OLE extraction
    if not test_enhanced_ole_extraction():
        success = False

    # Test CLI interface
    if not test_cli_interface():
        success = False

    if not test_html_report():
        success = False

    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed!")
        sys.exit(0)
    else:
        print("💥 Some tests failed!")
        sys.exit(1)
