# Office File Analyzer

A comprehensive Python tool for analyzing Microsoft Office documents to detect malicious content, extract metadata, analyze macros, and identify security threats.

## Features

- **Comprehensive File Support**: Supports both modern (OOXML) and legacy Office formats
  - Word: `.docx`, `.docm`, `.dotx`, `.dotm`, `.doc`, `.dot`
  - Excel: `.xlsx`, `.xlsm`, `.xltx`, `.xltm`, `.xls`, `.xlt`
  - PowerPoint: `.pptx`, `.pptm`, `.potx`, `.potm`, `.ppt`, `.pot`

- **Advanced Threat Detection**:
  - VBA/VBS macro analysis with deobfuscation
  - Risk scoring algorithm (0-100)
  - Threat level classification (None/Low/Medium/High/Critical)
  - Indicators of Compromise (IoC) extraction

- **Deep Content Analysis**:
  - Metadata extraction (author, company, creation time, etc.)
  - Network indicators (URLs, IPs, domains)
  - Embedded objects and files
  - Hidden content detection
  - DDE (Dynamic Data Exchange) links
  - Form controls analysis
  - External references

- **Macro Analysis**:
  - Auto-execution detection
  - Obfuscation scoring (0-10)
  - Suspicious API detection
  - Technique analysis (Base64, string concatenation, etc.)
  - Payload deobfuscation

- **Flexible Output**:
  - Detailed text reports
  - JSON format for programmatic use
  - Comprehensive IoC lists

## Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Required Libraries

The tool uses several specialized libraries for Office file analysis:

- **Office parsing**: `python-docx`, `openpyxl`, `python-pptx`
- **Legacy format support**: `oletools`, `olefile`
- **Macro analysis**: `vba-parser`, `pyvba`
- **Network analysis**: `requests`, `validators`
- **Cryptography**: `pycryptodome`
- **Pattern matching**: `yara-python`

## Usage

### Basic Usage

```bash
python analyze_office.py document.docx
```

### Advanced Usage

```bash
# Analyze with JSON output
python analyze_office.py suspicious.xlsm --output-format json

# Save report to file
python analyze_office.py presentation.pptx --output report.txt

# Disable network checks (offline mode)
python analyze_office.py document.docm --no-network

# Verbose mode
python analyze_office.py document.xlsx --verbose
```

### Command Line Options

```
positional arguments:
  file_path             Path to the Office file to analyze

options:
  -h, --help            Show help message and exit
  --output OUTPUT, -o OUTPUT
                        Output file path for the report (default: print to stdout)
  --output-format {text,json}, -f {text,json}
                        Output format for the report (default: text)
  --no-network          Disable network-based checks and reputation lookups
  --verbose, -v         Enable verbose output
  --version             Show program's version number and exit
```

## Sample Output

The tool generates comprehensive reports following this structure:

```
================================================================================
OFFICE FILE ANALYSIS REPORT
================================================================================

FILE INFORMATION
----------------------------------------
File Path: /path/to/document.docx
File Size: 45,672 bytes
SHA256: e3c7d21fe4...ab2f
MD5: a1b2c3d4e5f6...
Analysis Time: 2024-10-14 15:30:45
Document Entropy: 6.87

AI VERDICT & RISK SCORING
----------------------------------------
Threat Level: High
Risk Score: 92/100
Classification: Malicious Macro Dropper with Network C2

Risk Factors:
  1. Auto-executing macro detected
  2. Suspicious APIs: CreateObject, Shell, WScript.Shell
  3. PowerShell execution detected
  4. Network activity detected in macro
  5. High entropy (6.87) - possible packed content

FILE METADATA
----------------------------------------
Document Title: Invoice_Payment_Details
Subject: Urgent Payment Required
Author: admin
Company: N/A
Manager: N/A
Template: N/A
Last Saved By: user
Document Version: N/A
Language: en-US
Office Version: 16.0
Password-Protected: No
Embedded Files: Yes

EXTRACTED URL & NETWORK INDICATORS
----------------------------------------
Extracted URLs/domains/IPs:
  - http://malicious-domain.com/payload.exe
  - 185.223.56.112

Use of shortened URLs: No
WebDAV or SMB paths: No
Redirection chains: None

EMBEDDED OBJECTS
----------------------------------------
Embedded Files: None

Macros:
  - AutoOpen
    SHA256: a1b2c3d4e5f6789...
    Entry Point: Yes

Auto Execution: Yes

External References: None

DDE (Dynamic Data Exchange) links: None
Form controls: None
Hidden content: None

VBA/VBS MACRO EXTRACTION
----------------------------------------
Macro: AutoOpen
Obfuscation Score: 8/10
High obfuscation detected: String concatenation, Base64 encoding, CharCode conversion
Auto-execution: Yes
Auto-execution triggers: AutoOpen(), Document_Open(), etc.

Suspicious APIs:
  - CreateObject
  - WScript.Shell
  - Shell

Techniques Detected:
  • String Concatenation: Yes
  • Base64 Encoding: Yes
  • Hex Encoding: No
  • Char Code Conversion: Yes
  • Environment Checks: Yes
  • Junk Code: No
  • Dynamic Function Calls: Yes
  • Registry Access: No
  • File Operations: Yes
  • Network Activity: Yes

Detected payloads:
  PowerShell command detected: powershell -exec bypass -enc SQBmACgAWwBh...

INDICATORS OF COMPROMISE (IoCs)
----------------------------------------
SHA256: e3c7d21fe4...ab2f

Macros:
  - AutoOpen (confidence: 90%)
    Auto-executing VBA macro

Api_calls:
  - CreateObject (confidence: 80%)
    Suspicious API call in macro AutoOpen
  - WScript.Shell (confidence: 80%)
    Suspicious API call in macro AutoOpen

Urls:
  - http://malicious-domain.com/payload.exe (confidence: 70%)
    URL found in document

Ips:
  - 185.223.56.112 (confidence: 80%)
    IP address found in document

================================================================================
Report generated at: 2024-10-14 15:30:47
================================================================================
```

## Exit Codes

The tool returns different exit codes based on the analysis results:

- `0`: Clean document or low threat
- `1`: Medium threat detected or analysis error
- `2`: High or critical threat detected
- `130`: Analysis interrupted by user

## API Usage

You can also use the analyzer programmatically:

```python
from office_analyzer import OfficeAnalyzer
from office_analyzer.reporting import ReportGenerator

# Initialize analyzer
analyzer = OfficeAnalyzer(enable_network_checks=True)

# Analyze file
result = analyzer.analyze_file('document.docx')

# Generate report
reporter = ReportGenerator()
text_report = reporter.generate_detailed_report(result)
json_report = reporter.generate_json_report(result)

# Save to file
reporter.save_report(result, 'report.txt', 'text')
reporter.save_report(result, 'report.json', 'json')
```

## Security Notes

- The tool performs static analysis only - it does not execute any code
- Network checks are optional and can be disabled with `--no-network`
- All analysis is performed locally; no data is sent to external services
- The tool is designed for security research and malware analysis

## Troubleshooting

### Common Issues

1. **Missing dependencies**: Ensure all required packages are installed
   ```bash
   pip install -r requirements.txt
   ```

2. **Unsupported file format**: Check that your file extension is supported
   ```bash
   python analyze_office.py --help
   ```

3. **Permission errors**: Ensure you have read access to the file being analyzed

4. **Memory issues with large files**: The tool loads files into memory; very large files may require more RAM

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for security research, malware analysis, and educational purposes only. Users are responsible for ensuring they have appropriate permissions to analyze files and comply with applicable laws and regulations.