# Office File Analyzer

A comprehensive Python tool for analyzing Microsoft Office documents to detect malicious content, extract metadata, analyze macros, and identify security threats.

## 🚀 Features

- **Advanced Threat Detection**: VBA/VBS macro analysis with deobfuscation
- **Risk Scoring**: Intelligent risk assessment (0-100 scale)
- **Comprehensive Analysis**: Metadata, network indicators, embedded objects
- **IoC Extraction**: Indicators of Compromise with confidence scoring
- **Flexible Output**: Text and JSON reporting formats

## 📁 Repository Structure

This repository contains the complete Office File Analyzer implementation:

- `analyze_office.py` - Main CLI interface
- `src/office_analyzer/` - Core analysis engine
- `requirements.txt` - Python dependencies  
- `README.md` - Complete documentation
- `test_basic.py` - Test suite

## 🔧 Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/analyzer.git
cd analyzer

# Install dependencies
pip install -r requirements.txt

# Analyze a file
python analyze_office.py document.docx
```

## 📖 Documentation

See the complete documentation in the feature branch for:
- Installation instructions
- Usage examples
- API documentation
- Troubleshooting guide

## 🛠 Development

The main development happens in feature branches. The current implementation is in the `feature/office-analyzer-implementation` branch.

## 📜 License

This project is for security research and malware analysis purposes.

---

**Note**: Replace `YOUR_USERNAME` with your actual GitHub username.