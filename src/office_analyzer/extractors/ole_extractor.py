"""
Enhanced OLE object and macro extractor for Office files.

This module provides deep analysis of OLE objects and comprehensive macro extraction
with obfuscation detection, suspicious content analysis, and threat scoring.
"""

import hashlib
import re
import base64
import zipfile
import io
import logging
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path

try:
    import olefile
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    from oletools.oleobj import OleNativeStream
    from oletools import msodde
except ImportError:
    olefile = None
    VBA_Parser = None
    OleNativeStream = None
    msodde = None
    TYPE_OLE = None
    TYPE_OpenXML = None

from ..models import OLEObjectInfo, MacroInfo
from ..utils import is_base64_string

logger = logging.getLogger(__name__)


class EnhancedOLEExtractor:
    """
    Enhanced extractor for OLE objects and macros with deep analysis capabilities.
    
    Features:
    - Comprehensive OLE object extraction and analysis
    - Advanced macro extraction with obfuscation detection
    - Suspicious content and API detection
    - Hex/Base64 string extraction
    - Code complexity and threat scoring
    """

    def __init__(self):
        """Initialize the enhanced OLE extractor."""
        self.suspicious_apis = [
            # System and Process APIs
            "CreateObject", "GetObject", "Shell", "WScript.Shell", "WScript.Network",
            "Scripting.FileSystemObject", "CallByName", "Execute", "ExecuteGlobal", 
            "Eval", "Run", "SendKeys", "Sleep", "Timer",
            
            # Application APIs
            "InternetExplorer.Application", "Excel.Application", "Word.Application",
            "PowerPoint.Application", "Outlook.Application", "Access.Application",
            
            # Network and Download APIs
            "URLDownloadToFile", "WinHttp.WinHttpRequest", "MSXML2.XMLHTTP",
            "MSXML2.DOMDocument", "MSXML2.FreeThreadedDOMDocument", "InternetOpen",
            "InternetOpenUrl", "InternetReadFile", "URLDownloadToFileA",
            
            # File and Registry APIs
            "ADODB.Stream", "Scripting.Dictionary", "RegRead", "RegWrite", "RegDelete",
            "FileSystemObject", "TextStream", "BinaryStream", "CopyFile", "MoveFile",
            "DeleteFile", "CreateFolder", "DeleteFolder",
            
            # Crypto and Encoding APIs
            "CryptStringToBinary", "CryptBinaryToString", "Base64Decode", "Base64Encode",
            "RC4", "XOR", "ROT13", "Caesar",
            
            # PowerShell and Command Line
            "powershell", "cmd.exe", "rundll32", "regsvr32", "mshta", "cscript", "wscript",
            
            # Windows APIs
            "kernel32", "ntdll", "user32", "advapi32", "wininet", "urlmon", "CreateProcess",
            "VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", "LoadLibrary",
            "GetProcAddress", "SetWindowsHook", "FindWindow", "PostMessage", "SendMessage"
        ]

        self.auto_execution_keywords = [
            # Document Events
            "AutoOpen", "AutoExec", "AutoNew", "AutoClose", "AutoExit",
            "Document_Open", "Document_Close", "Document_New", "Document_BeforeClose",
            "Workbook_Open", "Workbook_Close", "Workbook_Activate", "Workbook_Deactivate",
            "Auto_Open", "Auto_Close", "Auto_Exec", 
            
            # Application Events
            "Application_DocumentOpen", "Application_Quit", "Application_NewDocument",
            "Worksheet_Activate", "Worksheet_SelectionChange", "Worksheet_Change",
            
            # Form and Control Events
            "UserForm_Initialize", "UserForm_Activate", "CommandButton_Click",
            "Private Sub", "Public Sub", "Function", "Sub Workbook_Open"
        ]

        self.obfuscation_patterns = [
            # String obfuscation
            r'Chr\(\d+\)',  # Chr(65)
            r'ChrW\(\d+\)',  # ChrW(65)
            r'Asc\("[^"]*"\)',  # Asc("A")
            r'&H[0-9A-Fa-f]+',  # Hex values
            r'[A-Za-z0-9+/]{20,}={0,2}',  # Base64
            
            # Variable name obfuscation
            r'\b[IlO0]{2,}\b',  # Lookalike characters
            r'\b[a-zA-Z]{15,}\b',  # Very long variable names
            
            # Code structure obfuscation
            r':\s*\w+',  # Multiple statements on one line
            r'_\s*$',  # Line continuation
            r'^\s*\'.*$',  # Comment lines (potential hiding)
        ]

    def extract_ole_objects(self, file_path: str) -> List[OLEObjectInfo]:
        """
        Extract OLE objects from an Office file.
        
        Args:
            file_path: Path to the Office file
            
        Returns:
            List of OLEObjectInfo objects containing detailed OLE object information
        """
        ole_objects = []
        
        try:
            # Try to handle as OLE file first
            if olefile and olefile.isOleFile(file_path):
                ole_objects.extend(self._extract_ole_objects_from_ole(file_path))
            
            # Try to handle as OOXML (zip-based) file
            ole_objects.extend(self._extract_ole_objects_from_ooxml(file_path))
            
        except Exception as e:
            logger.warning(f"Error extracting OLE objects from {file_path}: {e}")
            
        return ole_objects

    def _extract_ole_objects_from_ole(self, file_path: str) -> List[OLEObjectInfo]:
        """Extract OLE objects from legacy OLE format files."""
        ole_objects = []
        
        try:
            with olefile.OleFileIO(file_path) as ole:
                # List all streams
                for stream_path in ole.listdir():
                    stream_name = '/'.join(stream_path)
                    
                    try:
                        # Get stream info
                        stream_size = ole._olestream_size(stream_path)
                        stream_data = ole.openstream(stream_path).read()
                        
                        # Calculate hashes
                        sha256_hash = hashlib.sha256(stream_data).hexdigest()
                        md5_hash = hashlib.md5(stream_data).hexdigest()
                        
                        # Analyze stream content
                        object_type = self._determine_ole_object_type(stream_name, stream_data)
                        is_macro = self._is_macro_stream(stream_name, stream_data)
                        is_embedded = self._is_embedded_file(stream_data)
                        suspicious_content = self._analyze_suspicious_content(stream_data)
                        
                        ole_object = OLEObjectInfo(
                            section_id=stream_name,
                            section_name=stream_name.split('/')[-1],
                            section_size=stream_size,
                            object_type=object_type,
                            content_type=self._detect_content_type(stream_data),
                            is_macro=is_macro,
                            is_embedded_file=is_embedded,
                            hash_sha256=sha256_hash,
                            hash_md5=md5_hash,
                            suspicious_content=suspicious_content
                        )
                        
                        ole_objects.append(ole_object)
                        
                    except Exception as e:
                        logger.debug(f"Error processing stream {stream_name}: {e}")
                        continue
                        
        except Exception as e:
            logger.warning(f"Error reading OLE file {file_path}: {e}")
            
        return ole_objects

    def _extract_ole_objects_from_ooxml(self, file_path: str) -> List[OLEObjectInfo]:
        """Extract OLE objects from OOXML (zip-based) format files."""
        ole_objects = []
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                for file_info in zf.filelist:
                    if file_info.is_dir():
                        continue
                        
                    try:
                        file_data = zf.read(file_info.filename)
                        
                        # Calculate hashes
                        sha256_hash = hashlib.sha256(file_data).hexdigest()
                        md5_hash = hashlib.md5(file_data).hexdigest()
                        
                        # Analyze content
                        object_type = self._determine_ooxml_object_type(file_info.filename, file_data)
                        is_macro = self._is_macro_content(file_info.filename, file_data)
                        is_embedded = self._is_embedded_file(file_data)
                        suspicious_content = self._analyze_suspicious_content(file_data)
                        
                        ole_object = OLEObjectInfo(
                            section_id=file_info.filename,
                            section_name=Path(file_info.filename).name,
                            section_size=file_info.file_size,
                            object_type=object_type,
                            content_type=self._detect_content_type(file_data),
                            is_macro=is_macro,
                            is_embedded_file=is_embedded,
                            hash_sha256=sha256_hash,
                            hash_md5=md5_hash,
                            suspicious_content=suspicious_content
                        )
                        
                        ole_objects.append(ole_object)
                        
                    except Exception as e:
                        logger.debug(f"Error processing file {file_info.filename}: {e}")
                        continue
                        
        except zipfile.BadZipFile:
            # Not a zip file, skip OOXML extraction
            pass
        except Exception as e:
            logger.warning(f"Error reading OOXML file {file_path}: {e}")
            
        return ole_objects

    def extract_enhanced_macros(self, file_path: str) -> List[MacroInfo]:
        """
        Extract macros with enhanced analysis including obfuscation detection.
        
        Args:
            file_path: Path to the Office file
            
        Returns:
            List of MacroInfo objects with comprehensive analysis
        """
        macros = []
        
        if not VBA_Parser:
            logger.warning("oletools VBA_Parser not available")
            return macros
            
        try:
            vba_parser = VBA_Parser(file_path)
            
            if vba_parser.detect_vba_macros():
                for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                    if vba_code and vba_code.strip():
                        macro_info = self._analyze_enhanced_macro(vba_filename, vba_code)
                        macros.append(macro_info)
                        
            vba_parser.close()
            
        except Exception as e:
            logger.warning(f"Error extracting macros from {file_path}: {e}")
            
        return macros

    def _analyze_enhanced_macro(self, name: str, code: str) -> MacroInfo:
        """
        Perform enhanced analysis of a macro including obfuscation and threat detection.
        
        Args:
            name: Name of the macro
            code: VBA/VBS code content
            
        Returns:
            MacroInfo object with comprehensive analysis
        """
        # Calculate hashes
        code_bytes = code.encode('utf-8')
        sha256_hash = hashlib.sha256(code_bytes).hexdigest()
        md5_hash = hashlib.md5(code_bytes).hexdigest()
        
        # Basic metrics
        lines = code.split('\n')
        line_count = len([line for line in lines if line.strip()])
        
        # Initialize macro info with enhanced fields
        macro_info = MacroInfo(
            name=name,
            content=code,
            hash_sha256=sha256_hash,
            hash_md5=md5_hash,
            macro_type=self._determine_macro_type(code),
            line_count=line_count
        )
        
        # Enhanced analysis
        macro_info.auto_execution = self._check_auto_execution(code)
        macro_info.entry_point = macro_info.auto_execution
        macro_info.suspicious_apis = self._find_suspicious_apis(code)
        macro_info.obfuscation_score = self._calculate_enhanced_obfuscation_score(code)
        macro_info.complexity_score = self._calculate_complexity_score(code)
        macro_info.obfuscation_techniques = self._detect_obfuscation_techniques(code)
        macro_info.suspicious_strings = self._extract_suspicious_strings(code)
        macro_info.hex_strings = self._extract_hex_strings(code)
        macro_info.base64_strings = self._extract_base64_strings(code)
        macro_info.techniques = self._detect_advanced_techniques(code)
        macro_info.deobfuscated_payload = self._enhanced_deobfuscation(code)
        
        return macro_info

    def _determine_ole_object_type(self, stream_name: str, data: bytes) -> str:
        """Determine the type of OLE object based on stream name and content."""
        stream_lower = stream_name.lower()
        
        if 'macro' in stream_lower or 'vba' in stream_lower:
            return 'VBA_Macro'
        elif stream_lower.endswith('objinfo'):
            return 'Object_Info'
        elif stream_lower.endswith('objpool'):
            return 'Object_Pool'
        elif 'ole' in stream_lower and 'native' in stream_lower:
            return 'OLE_Native_Stream'
        elif stream_lower.startswith('_'):
            return 'OLE_Stream'
        elif len(data) > 0 and data[:4] == b'\\x00\\x00\\x00\\x00':
            return 'Binary_Object'
        else:
            return 'Unknown_Stream'

    def _determine_ooxml_object_type(self, filename: str, data: bytes) -> str:
        """Determine the type of object in OOXML files."""
        filename_lower = filename.lower()
        
        if filename_lower.endswith('.bin'):
            return 'Binary_Object'
        elif 'vbaproject' in filename_lower:
            return 'VBA_Project'
        elif filename_lower.endswith('.xml'):
            return 'XML_Part'
        elif filename_lower.endswith('.rels'):
            return 'Relationship_Part'
        elif 'embeddings' in filename_lower:
            return 'Embedded_Object'
        elif 'media' in filename_lower:
            return 'Media_Object'
        else:
            return 'OOXML_Part'

    def _is_macro_stream(self, stream_name: str, data: bytes) -> bool:
        """Check if a stream contains macro code."""
        stream_lower = stream_name.lower()
        return ('macro' in stream_lower or 
                'vba' in stream_lower or 
                'project' in stream_lower or
                self._has_vba_signatures(data))

    def _is_macro_content(self, filename: str, data: bytes) -> bool:
        """Check if OOXML content contains macros."""
        filename_lower = filename.lower()
        return ('vba' in filename_lower or 
                'macro' in filename_lower or
                filename_lower.endswith('.bin') and self._has_vba_signatures(data))

    def _has_vba_signatures(self, data: bytes) -> bool:
        """Check for VBA signatures in binary data."""
        vba_signatures = [
            b'Microsoft Visual Basic',
            b'VBA',
            b'Sub ',
            b'Function ',
            b'Attribute VB_',
            b'Option Explicit'
        ]
        
        try:
            data_str = data.decode('utf-8', errors='ignore').upper()
            return any(sig.decode('utf-8').upper() in data_str for sig in vba_signatures)
        except:
            return False

    def _is_embedded_file(self, data: bytes) -> bool:
        """Check if data represents an embedded file."""
        if len(data) < 20:
            return False
            
        # Check for common file signatures
        signatures = [
            b'\\x50\\x4B\\x03\\x04',  # ZIP
            b'\\x89PNG',  # PNG
            b'\\xFF\\xD8\\xFF',  # JPEG
            b'%PDF',  # PDF
            b'MZ',  # PE/EXE
            b'\\x7fELF',  # ELF
        ]
        
        return any(data.startswith(sig) for sig in signatures)

    def _detect_content_type(self, data: bytes) -> Optional[str]:
        """Detect the content type of binary data."""
        if len(data) < 4:
            return None
            
        # Check magic bytes
        if data.startswith(b'\\x50\\x4B\\x03\\x04'):
            return 'application/zip'
        elif data.startswith(b'\\x89PNG'):
            return 'image/png'
        elif data.startswith(b'\\xFF\\xD8\\xFF'):
            return 'image/jpeg'
        elif data.startswith(b'%PDF'):
            return 'application/pdf'
        elif data.startswith(b'MZ'):
            return 'application/x-msdownload'
        elif b'<' in data[:100] and b'>' in data[:100]:
            return 'text/xml'
        else:
            return 'application/octet-stream'

    def _analyze_suspicious_content(self, data: bytes) -> List[str]:
        """Analyze data for suspicious content patterns."""
        suspicious = []
        
        try:
            # Convert to string for analysis
            text = data.decode('utf-8', errors='ignore')
            text_upper = text.upper()
            
            # Check for suspicious APIs
            for api in self.suspicious_apis:
                if api.upper() in text_upper:
                    suspicious.append(f"Suspicious API: {api}")
                    
            # Check for URLs
            urls = re.findall(r'https?://[^\\s"\'<>]+', text, re.IGNORECASE)
            if urls:
                suspicious.append(f"URLs found: {len(urls)} URLs")
                
            # Check for IP addresses
            ips = re.findall(r'\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b', text)
            if ips:
                suspicious.append(f"IP addresses: {len(ips)} IPs")
                
            # Check for base64 patterns
            base64_matches = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', text)
            if base64_matches:
                suspicious.append(f"Base64 patterns: {len(base64_matches)} found")
                
            # Check for hex patterns
            hex_matches = re.findall(r'&H[0-9A-Fa-f]+|0x[0-9A-Fa-f]+', text)
            if hex_matches:
                suspicious.append(f"Hex patterns: {len(hex_matches)} found")
                
        except Exception as e:
            logger.debug(f"Error analyzing suspicious content: {e}")
            
        return suspicious

    def _determine_macro_type(self, code: str) -> str:
        """Determine the type of macro based on code content."""
        code_upper = code.upper()
        
        if 'ATTRIBUTE VB_' in code_upper:
            return 'VBA'
        elif 'WSCRIPT' in code_upper or 'CSCRIPT' in code_upper:
            return 'VBScript'
        elif 'JAVASCRIPT' in code_upper or 'JSCRIPT' in code_upper:
            return 'JavaScript'
        elif 'SUB ' in code_upper or 'FUNCTION ' in code_upper:
            return 'VBA'
        else:
            return 'Unknown'

    def _check_auto_execution(self, code: str) -> bool:
        """Enhanced auto-execution detection."""
        code_upper = code.upper()
        
        for keyword in self.auto_execution_keywords:
            if keyword.upper() in code_upper:
                return True
                
        return False

    def _find_suspicious_apis(self, code: str) -> List[str]:
        """Enhanced suspicious API detection."""
        found_apis = []
        code_upper = code.upper()
        
        for api in self.suspicious_apis:
            if api.upper() in code_upper:
                found_apis.append(api)
                
        return list(set(found_apis))  # Remove duplicates

    def _calculate_enhanced_obfuscation_score(self, code: str) -> int:
        """
        Calculate enhanced obfuscation score (0-10).
        
        Analyzes multiple obfuscation techniques and assigns weighted scores.
        """
        score = 0
        
        # String concatenation and building
        concat_patterns = len(re.findall(r'["\']\\s*[+&]\\s*["\']', code))
        if concat_patterns > 5:
            score += 3
        elif concat_patterns > 0:
            score += 1
            
        # Character code conversion
        char_conversions = len(re.findall(r'Chr\\(|ChrW\\(|Asc\\(', code, re.IGNORECASE))
        if char_conversions > 10:
            score += 3
        elif char_conversions > 0:
            score += 1
            
        # Base64 patterns
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code)
        valid_base64 = sum(1 for pattern in base64_patterns if is_base64_string(pattern))
        if valid_base64 > 0:
            score += 2
            
        # Hex encoding
        hex_patterns = len(re.findall(r'&H[0-9A-Fa-f]+', code))
        if hex_patterns > 5:
            score += 2
        elif hex_patterns > 0:
            score += 1
            
        # Variable name obfuscation
        variables = re.findall(r'\\b[a-zA-Z_][a-zA-Z0-9_]*\\b', code)
        if variables:
            # Check for random-looking variable names
            random_vars = [v for v in variables if len(v) > 8 and 
                          sum(1 for c in v if c.isupper()) / len(v) > 0.5]
            if len(random_vars) > 5:
                score += 2
                
        # Code structure obfuscation
        if ':' in code and len(code.split(':')) > len(code.split('\\n')) * 0.8:
            score += 1  # Multiple statements per line
            
        # Line continuation abuse
        line_continuations = code.count('_\\n') + code.count('_ \\n')
        if line_continuations > 10:
            score += 1
            
        return min(score, 10)

    def _calculate_complexity_score(self, code: str) -> int:
        """Calculate code complexity score (0-10)."""
        lines = code.split('\\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        # Basic metrics
        line_count = len(non_empty_lines)
        
        # Control structures
        control_keywords = ['If', 'For', 'While', 'Do', 'Select', 'Case', 'Loop']
        control_count = sum(code.upper().count(keyword.upper()) for keyword in control_keywords)
        
        # Functions and subroutines
        func_count = code.upper().count('FUNCTION ') + code.upper().count('SUB ')
        
        # Calculate complexity
        complexity = 0
        
        if line_count > 100:
            complexity += 3
        elif line_count > 50:
            complexity += 2
        elif line_count > 20:
            complexity += 1
            
        if control_count > 20:
            complexity += 3
        elif control_count > 10:
            complexity += 2
        elif control_count > 5:
            complexity += 1
            
        if func_count > 10:
            complexity += 2
        elif func_count > 5:
            complexity += 1
            
        # Nested structures (simplified detection)
        nesting_level = max(line.count('    ') for line in lines if line.strip())
        if nesting_level > 6:
            complexity += 2
        elif nesting_level > 3:
            complexity += 1
            
        return min(complexity, 10)

    def _detect_obfuscation_techniques(self, code: str) -> List[str]:
        """Detect specific obfuscation techniques used."""
        techniques = []
        
        # String concatenation
        if '+' in code and '"' in code:
            techniques.append('String_Concatenation')
            
        # Character code conversion
        if re.search(r'Chr\\(|ChrW\\(|Asc\\(', code, re.IGNORECASE):
            techniques.append('Character_Code_Conversion')
            
        # Base64 encoding
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code)
        if any(is_base64_string(pattern) for pattern in base64_patterns):
            techniques.append('Base64_Encoding')
            
        # Hex encoding
        if re.search(r'&H[0-9A-Fa-f]+', code):
            techniques.append('Hex_Encoding')
            
        # Variable name obfuscation
        variables = re.findall(r'\\b[a-zA-Z_][a-zA-Z0-9_]*\\b', code)
        if any(len(v) > 15 or re.match(r'^[IlO0]+$', v) for v in variables):
            techniques.append('Variable_Name_Obfuscation')
            
        # Dynamic execution
        if re.search(r'Execute|Eval|CallByName', code, re.IGNORECASE):
            techniques.append('Dynamic_Execution')
            
        # Anti-analysis
        anti_analysis_keywords = ['Sleep', 'Timer', 'Now', 'UserName', 'ComputerName']
        if any(keyword in code for keyword in anti_analysis_keywords):
            techniques.append('Anti_Analysis')
            
        return techniques

    def _extract_suspicious_strings(self, code: str) -> List[str]:
        """Extract suspicious string patterns from code."""
        suspicious = []
        
        # PowerShell commands
        ps_patterns = re.findall(r'powershell[^"\'\\n]*', code, re.IGNORECASE)
        suspicious.extend([f"PowerShell: {ps[:50]}..." for ps in ps_patterns])
        
        # Command line executables
        cmd_patterns = re.findall(r'(?:cmd|rundll32|regsvr32|mshta|cscript|wscript)[^"\'\\n]*', 
                                 code, re.IGNORECASE)
        suspicious.extend([f"Command: {cmd[:50]}..." for cmd in cmd_patterns])
        
        # URLs
        urls = re.findall(r'https?://[^\\s"\'<>]+', code, re.IGNORECASE)
        suspicious.extend([f"URL: {url}" for url in urls])
        
        # File paths
        paths = re.findall(r'[A-Za-z]:\\\\[^"\'\\n]*', code)
        suspicious.extend([f"Path: {path}" for path in paths])
        
        return suspicious[:10]  # Limit to prevent spam

    def _extract_hex_strings(self, code: str) -> List[str]:
        """Extract hex-encoded strings from code."""
        hex_patterns = re.findall(r'&H[0-9A-Fa-f]+|0x[0-9A-Fa-f]+', code)
        return hex_patterns[:20]  # Limit to prevent spam

    def _extract_base64_strings(self, code: str) -> List[str]:
        """Extract base64-encoded strings from code."""
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code)
        valid_base64 = [pattern for pattern in base64_patterns if is_base64_string(pattern)]
        return valid_base64[:10]  # Limit to prevent spam

    def _detect_advanced_techniques(self, code: str) -> Dict[str, bool]:
        """Detect advanced evasion and attack techniques."""
        techniques = {
            'string_concatenation': False,
            'base64_encoding': False,
            'hex_encoding': False,
            'char_code_conversion': False,
            'environment_checks': False,
            'anti_analysis': False,
            'dynamic_execution': False,
            'registry_access': False,
            'file_operations': False,
            'network_activity': False,
            'process_injection': False,
            'privilege_escalation': False,
            'persistence': False,
            'lateral_movement': False
        }
        
        code_upper = code.upper()
        
        # Existing techniques
        if '+' in code and '"' in code:
            techniques['string_concatenation'] = True
            
        base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code)
        if any(is_base64_string(pattern) for pattern in base64_patterns):
            techniques['base64_encoding'] = True
            
        if re.search(r'&H[0-9A-Fa-f]+', code):
            techniques['hex_encoding'] = True
            
        if any(func in code_upper for func in ['CHR(', 'CHRW(', 'ASC(']):
            techniques['char_code_conversion'] = True
            
        # Anti-analysis techniques
        anti_keywords = ['SLEEP', 'TIMER', 'NOW', 'USERNAME', 'COMPUTERNAME', 'ENVIRON']
        if any(keyword in code_upper for keyword in anti_keywords):
            techniques['anti_analysis'] = True
            
        # Dynamic execution
        if any(func in code_upper for func in ['EXECUTE', 'EVAL', 'CALLBYNAME']):
            techniques['dynamic_execution'] = True
            
        # Process injection
        injection_apis = ['VIRTUALALLOCEX', 'WRITEPROCESSMEMORY', 'CREATEREMOTETHREAD']
        if any(api in code_upper for api in injection_apis):
            techniques['process_injection'] = True
            
        # Privilege escalation
        priv_keywords = ['RUNAS', 'ELEVATE', 'ADMIN', 'SYSTEM', 'TOKEN']
        if any(keyword in code_upper for keyword in priv_keywords):
            techniques['privilege_escalation'] = True
            
        # Persistence
        persist_keywords = ['STARTUP', 'REGISTRY', 'SCHEDULED', 'SERVICE', 'AUTORUN']
        if any(keyword in code_upper for keyword in persist_keywords):
            techniques['persistence'] = True
            
        # Lateral movement
        lateral_keywords = ['PSEXEC', 'WMI', 'REMOTESHELL', 'COPY', 'SHARE']
        if any(keyword in code_upper for keyword in lateral_keywords):
            techniques['lateral_movement'] = True
            
        return techniques

    def _enhanced_deobfuscation(self, code: str) -> Optional[str]:
        """Enhanced deobfuscation with multiple techniques."""
        try:
            # Try base64 decoding
            base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', code)
            for pattern in base64_patterns:
                if is_base64_string(pattern):
                    try:
                        decoded = base64.b64decode(pattern).decode('utf-8', errors='ignore')
                        if len(decoded) > 10 and any(c.isalpha() for c in decoded):
                            return f"Base64 decoded: {decoded[:200]}..."
                    except:
                        continue
                        
            # Try character code deobfuscation
            char_pattern = re.search(r'Chr\\((\\d+)\\)', code)
            if char_pattern:
                try:
                    char_code = int(char_pattern.group(1))
                    if 32 <= char_code <= 126:  # Printable ASCII
                        return f"Character code {char_code} = '{chr(char_code)}'"
                except:
                    pass
                    
            # Look for PowerShell commands
            ps_match = re.search(r'powershell[^"\']*', code, re.IGNORECASE)
            if ps_match:
                return f"PowerShell command: {ps_match.group()[:100]}..."
                
            # Look for suspicious URLs
            url_match = re.search(r'https?://[^\\s"\'<>]+', code, re.IGNORECASE)
            if url_match:
                return f"Suspicious URL: {url_match.group()}"
                
        except Exception as e:
            logger.debug(f"Error in enhanced deobfuscation: {e}")
            
        return None