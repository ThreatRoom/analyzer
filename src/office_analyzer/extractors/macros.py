"""
VBA/VBS macro extractor and analyzer.
"""

import hashlib
import re
import base64
from typing import List

try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    from oletools.mraptor import MacroRaptor
except ImportError:
    VBA_Parser = None
    MacroRaptor = None
    TYPE_OLE = None
    TYPE_OpenXML = None

from ..models import MacroInfo
from ..utils import is_base64_string


class MacroExtractor:
    """Extracts and analyzes VBA/VBS macros from Office documents."""

    def __init__(self):
        """Initialize the macro extractor."""
        self.suspicious_apis = [
            "CreateObject",
            "GetObject",
            "Shell",
            "WScript.Shell",
            "WScript.Network",
            "Scripting.FileSystemObject",
            "InternetExplorer.Application",
            "Excel.Application",
            "Word.Application",
            "PowerPoint.Application",
            "URLDownloadToFile",
            "WinHttp.WinHttpRequest",
            "MSXML2.XMLHTTP",
            "ADODB.Stream",
            "CallByName",
            "Execute",
            "ExecuteGlobal",
            "Eval",
            "Run",
        ]

        self.auto_execution_keywords = [
            "AutoOpen",
            "AutoExec",
            "AutoNew",
            "AutoClose",
            "Document_Open",
            "Document_Close",
            "Document_New",
            "Workbook_Open",
            "Workbook_Close",
            "Workbook_Activate",
            "Auto_Open",
            "Auto_Close",
            "Auto_Exec",
        ]

    def extract(self, file_path: str) -> List[MacroInfo]:
        """
        Extract macros from an Office file.

        Args:
            file_path: Path to the Office file

        Returns:
            List of MacroInfo objects containing macro details
        """
        macros = []

        if not VBA_Parser:
            return macros

        try:
            vba_parser = VBA_Parser(file_path)

            if vba_parser.detect_vba_macros():
                for filename, stream_path, vba_filename, vba_code in vba_parser.extract_macros():
                    if vba_code and vba_code.strip():
                        macro_info = self._analyze_macro(vba_filename, vba_code)
                        macros.append(macro_info)

            vba_parser.close()

        except Exception:
            # If oletools fails, try alternative extraction methods
            pass

        return macros

    def _analyze_macro(self, name: str, code: str) -> MacroInfo:
        """
        Analyze a single macro for suspicious content.

        Args:
            name: Name of the macro
            code: VBA/VBS code content

        Returns:
            MacroInfo object with analysis results
        """
        # Calculate hashes
        code_bytes = code.encode("utf-8")
        sha256 = hashlib.sha256(code_bytes).hexdigest()
        md5 = hashlib.md5(code_bytes).hexdigest()

        # Initialize macro info
        macro_info = MacroInfo(name=name, content=code, hash_sha256=sha256, hash_md5=md5)

        # Check for auto-execution
        macro_info.auto_execution = self._check_auto_execution(code)
        macro_info.entry_point = macro_info.auto_execution

        # Find suspicious APIs
        macro_info.suspicious_apis = self._find_suspicious_apis(code)

        # Calculate obfuscation score
        macro_info.obfuscation_score = self._calculate_obfuscation_score(code)

        # Detect obfuscation techniques
        macro_info.techniques = self._detect_techniques(code)

        # Try to deobfuscate payload
        macro_info.deobfuscated_payload = self._deobfuscate_payload(code)

        return macro_info

    def _check_auto_execution(self, code: str) -> bool:
        """Check if macro contains auto-execution triggers."""
        code_upper = code.upper()

        for keyword in self.auto_execution_keywords:
            if keyword.upper() in code_upper:
                return True

        return False

    def _find_suspicious_apis(self, code: str) -> List[str]:
        """Find suspicious API calls in the macro code."""
        found_apis = []
        code_upper = code.upper()

        for api in self.suspicious_apis:
            if api.upper() in code_upper:
                found_apis.append(api)

        return found_apis

    def _calculate_obfuscation_score(self, code: str) -> int:
        """
        Calculate obfuscation score (0-10).

        Higher scores indicate more obfuscation.
        """
        score = 0

        # String concatenation
        if "+" in code and ("&" in code or "Chr(" in code):
            score += 2

        # Base64 patterns
        base64_patterns = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", code)
        if base64_patterns:
            score += 3

        # Character code conversion
        if "Chr(" in code or "ChrW(" in code or "Asc(" in code:
            score += 2

        # Hex patterns
        if re.search(r"&H[0-9A-Fa-f]+", code):
            score += 1

        # Variable name entropy (random-looking variables)
        variables = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", code)
        if variables:
            avg_entropy = sum(self._calculate_string_entropy(var) for var in variables[:10]) / min(len(variables), 10)
            if avg_entropy > 3.5:
                score += 2

        return min(score, 10)

    def _calculate_string_entropy(self, s: str) -> float:
        """Calculate entropy of a string."""
        if not s:
            return 0.0

        char_counts = {}
        for char in s.lower():
            char_counts[char] = char_counts.get(char, 0) + 1

        entropy = 0.0
        length = len(s)

        for count in char_counts.values():
            probability = count / length
            entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0

        return entropy

    def _detect_techniques(self, code: str) -> dict:
        """Detect various obfuscation and evasion techniques."""
        techniques = {
            "string_concatenation": False,
            "base64_encoding": False,
            "hex_encoding": False,
            "char_code_conversion": False,
            "environment_checks": False,
            "junk_code": False,
            "dynamic_function_calls": False,
            "registry_access": False,
            "file_operations": False,
            "network_activity": False,
        }

        code_upper = code.upper()

        # String concatenation
        if "+" in code and ("&" in code or '"' in code):
            techniques["string_concatenation"] = True

        # Base64 encoding
        base64_patterns = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", code)
        if any(is_base64_string(pattern) for pattern in base64_patterns):
            techniques["base64_encoding"] = True

        # Hex encoding
        if re.search(r"&H[0-9A-Fa-f]+", code):
            techniques["hex_encoding"] = True

        # Character code conversion
        if any(func in code_upper for func in ["CHR(", "CHRW(", "ASC("]):
            techniques["char_code_conversion"] = True

        # Environment checks
        env_keywords = ["ENVIRON", "USERNAME", "COMPUTERNAME", "OS"]
        if any(keyword in code_upper for keyword in env_keywords):
            techniques["environment_checks"] = True

        # Dynamic function calls
        if any(func in code_upper for func in ["CALLBYNAME", "GETOBJECT", "CREATEOBJECT"]):
            techniques["dynamic_function_calls"] = True

        # Registry access
        if any(reg in code_upper for reg in ["REGREAD", "REGWRITE", "REGISTRY"]):
            techniques["registry_access"] = True

        # File operations
        file_ops = ["OPEN", "WRITE", "READ", "COPY", "DELETE", "KILL", "MKDIR"]
        if any(op in code_upper for op in file_ops):
            techniques["file_operations"] = True

        # Network activity
        net_keywords = ["HTTP", "URL", "DOWNLOAD", "INTERNET", "WINHTTP"]
        if any(keyword in code_upper for keyword in net_keywords):
            techniques["network_activity"] = True

        # Junk code detection (simplified)
        lines = code.split("\n")
        empty_or_comment_lines = sum(1 for line in lines if not line.strip() or line.strip().startswith("'"))
        if len(lines) > 10 and (empty_or_comment_lines / len(lines)) > 0.3:
            techniques["junk_code"] = True

        return techniques

    def _deobfuscate_payload(self, code: str) -> str:
        """
        Attempt to deobfuscate the macro payload.

        This is a simplified deobfuscation - in practice, you'd want
        more sophisticated analysis.
        """
        try:
            # Look for base64 encoded strings
            base64_patterns = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", code)

            for pattern in base64_patterns:
                if is_base64_string(pattern):
                    try:
                        decoded = base64.b64decode(pattern).decode("utf-8", errors="ignore")
                        if len(decoded) > 10 and any(c.isalpha() for c in decoded):
                            return f"Base64 decoded payload: {decoded[:500]}..."
                    except Exception:
                        continue

            # Look for PowerShell commands
            ps_patterns = re.findall(r'powershell[^"\']*', code, re.IGNORECASE)
            if ps_patterns:
                return f"PowerShell command detected: {ps_patterns[0][:200]}..."

            # Look for URLs
            url_patterns = re.findall(r'https?://[^\s"\'<>]+', code, re.IGNORECASE)
            if url_patterns:
                return f"URL detected: {', '.join(url_patterns[:3])}"

        except Exception:
            pass

        return None
