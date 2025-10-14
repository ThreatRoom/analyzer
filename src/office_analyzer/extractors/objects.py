"""
Embedded objects and content extractor.
"""

import hashlib
import zipfile
from typing import List, Dict, Any
from pathlib import Path

from ..models import EmbeddedObject


class ObjectExtractor:
    """Extracts embedded objects and content from Office documents."""

    def __init__(self):
        """Initialize the object extractor."""
        pass

    def extract(self, file_path: str) -> List[EmbeddedObject]:
        """
        Extract embedded objects from an Office file.

        Args:
            file_path: Path to the Office file

        Returns:
            List of EmbeddedObject instances
        """
        objects = []
        file_path = Path(file_path)

        try:
            if file_path.suffix.lower() in [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]:
                objects = self._extract_from_modern_format(str(file_path))
            else:
                objects = self._extract_from_legacy_format(str(file_path))
        except Exception:
            pass

        return objects

    def extract_dde_links(self, file_path: str) -> List[str]:
        """Extract Dynamic Data Exchange (DDE) links."""
        dde_links = []

        try:
            # Look for DDE patterns in document content
            content = self._get_document_content(file_path)

            # DDE link patterns
            dde_patterns = [r"\\x13\\s*DDEAUTO\\s+[^\\x14]+\\x14", r"DDE\\s*\\([^)]+\\)", r"\\[\\s*\\w+\\s*\\]"]

            import re

            for pattern in dde_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                dde_links.extend(matches)

        except Exception:
            pass

        return dde_links

    def extract_form_controls(self, file_path: str) -> List[str]:
        """Extract form controls from the document."""
        controls = []

        try:
            content = self._get_document_content(file_path)

            # Look for form control patterns
            control_patterns = [
                r"<w:ffData>",
                r"<v:textbox>",
                r"<w:textInput>",
                r"<w:checkBox>",
                r"<w:dropDownList>",
                r"ActiveX",
            ]

            import re

            for pattern in control_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    controls.append(pattern.strip("<>"))

        except Exception:
            pass

        return controls

    def extract_hidden_content(self, file_path: str) -> List[str]:
        """Extract hidden content indicators."""
        hidden_content = []

        try:
            if Path(file_path).suffix.lower() in [".xlsx", ".xlsm"]:
                hidden_content.extend(self._extract_hidden_sheets(file_path))

            # Check for hidden text/shapes
            content = self._get_document_content(file_path)

            hidden_patterns = [
                r'w:hidden="true"',
                r'w:vanish="true"',
                r"visibility:hidden",
                r"display:none",
                r"<w:webHidden/>",
            ]

            import re

            for pattern in hidden_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    hidden_content.append(f"Hidden content: {pattern}")

        except Exception:
            pass

        return hidden_content

    def extract_external_references(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract external references from the document."""
        references = []

        try:
            if Path(file_path).suffix.lower() in [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]:
                references = self._extract_modern_references(file_path)
            else:
                references = self._extract_legacy_references(file_path)

        except Exception:
            pass

        return references

    def _extract_from_modern_format(self, file_path: str) -> List[EmbeddedObject]:
        """Extract objects from modern Office formats."""
        objects = []

        try:
            with zipfile.ZipFile(file_path, "r") as zip_file:
                for file_info in zip_file.filelist:
                    # Look for embedded files
                    if "/embeddings/" in file_info.filename or file_info.filename.startswith("embeddings/"):
                        obj = self._create_embedded_object(zip_file, file_info)
                        if obj:
                            objects.append(obj)

                    # Look for media files
                    elif "/media/" in file_info.filename or file_info.filename.startswith("media/"):
                        obj = self._create_media_object(zip_file, file_info)
                        if obj:
                            objects.append(obj)

        except Exception:
            pass

        return objects

    def _extract_from_legacy_format(self, file_path: str) -> List[EmbeddedObject]:
        """Extract objects from legacy Office formats."""
        objects = []

        try:
            # For legacy formats, we'd need to parse OLE structures
            # This is a simplified implementation
            with open(file_path, "rb") as f:
                data = f.read()

            # Look for embedded object signatures
            ole_signatures = [
                b"\\xd0\\xcf\\x11\\xe0\\xa1\\xb1\\x1a\\xe1",  # OLE signature
                b"PK\\x03\\x04",  # ZIP signature (embedded OOXML)
                b"\\x50\\x4b\\x03\\x04",  # Another ZIP signature
            ]

            for i, sig in enumerate(ole_signatures):
                if sig in data:
                    obj = EmbeddedObject(object_type=f"embedded_ole_{i}", name=f"embedded_object_{i}", size=len(sig))
                    objects.append(obj)

        except Exception:
            pass

        return objects

    def _create_embedded_object(self, zip_file: zipfile.ZipFile, file_info: zipfile.ZipInfo) -> EmbeddedObject:
        """Create an EmbeddedObject from a ZIP file entry."""
        try:
            data = zip_file.read(file_info.filename)

            # Calculate hashes
            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()

            # Determine content type based on data
            content_type = self._detect_content_type(data)

            return EmbeddedObject(
                object_type="embedded_file",
                name=file_info.filename,
                size=file_info.file_size,
                hash_sha256=sha256,
                hash_md5=md5,
                content_type=content_type,
            )

        except Exception:
            return None

    def _create_media_object(self, zip_file: zipfile.ZipFile, file_info: zipfile.ZipInfo) -> EmbeddedObject:
        """Create an EmbeddedObject for media files."""
        try:
            data = zip_file.read(file_info.filename)

            sha256 = hashlib.sha256(data).hexdigest()
            md5 = hashlib.md5(data).hexdigest()
            content_type = self._detect_content_type(data)

            return EmbeddedObject(
                object_type="media_file",
                name=file_info.filename,
                size=file_info.file_size,
                hash_sha256=sha256,
                hash_md5=md5,
                content_type=content_type,
            )

        except Exception:
            return None

    def _detect_content_type(self, data: bytes) -> str:
        """Detect content type from binary data."""
        # Simple magic number detection
        if data.startswith(b"\\x89PNG"):
            return "image/png"
        elif data.startswith(b"\\xff\\xd8\\xff"):
            return "image/jpeg"
        elif data.startswith(b"GIF8"):
            return "image/gif"
        elif data.startswith(b"PK"):
            return "application/zip"
        elif data.startswith(b"%PDF"):
            return "application/pdf"
        elif data.startswith(b"\\xd0\\xcf\\x11\\xe0"):
            return "application/vnd.ms-office"
        else:
            return "application/octet-stream"

    def _get_document_content(self, file_path: str) -> str:
        """Get document content as string."""
        content = ""

        try:
            if Path(file_path).suffix.lower() in [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]:
                with zipfile.ZipFile(file_path, "r") as zip_file:
                    for file_info in zip_file.filelist:
                        if file_info.filename.endswith(".xml"):
                            try:
                                xml_content = zip_file.read(file_info.filename).decode("utf-8", errors="ignore")
                                content += xml_content + "\\n"
                            except Exception:
                                continue
            else:
                # For legacy formats, read as binary and extract strings
                with open(file_path, "rb") as f:
                    data = f.read()
                content = data.decode("utf-8", errors="ignore")

        except Exception:
            pass

        return content

    def _extract_hidden_sheets(self, file_path: str) -> List[str]:
        """Extract hidden sheets from Excel files."""
        hidden_sheets = []

        try:
            # Look for sheet visibility in workbook.xml
            content = self._get_document_content(file_path)

            import re

            # Look for hidden sheet patterns
            hidden_patterns = re.findall(r'<sheet[^>]*state="hidden"[^>]*name="([^"]*)"', content, re.IGNORECASE)
            hidden_sheets.extend([f"Hidden sheet: {name}" for name in hidden_patterns])

            very_hidden_patterns = re.findall(
                r'<sheet[^>]*state="veryHidden"[^>]*name="([^"]*)"', content, re.IGNORECASE
            )
            hidden_sheets.extend([f"Very hidden sheet: {name}" for name in very_hidden_patterns])

        except Exception:
            pass

        return hidden_sheets

    def _extract_modern_references(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract external references from modern Office formats."""
        references = []

        try:
            with zipfile.ZipFile(file_path, "r") as zip_file:
                # Look for external relationships
                for file_info in zip_file.filelist:
                    if file_info.filename.endswith(".rels"):
                        try:
                            rels_content = zip_file.read(file_info.filename).decode("utf-8", errors="ignore")
                            refs = self._parse_relationships(rels_content)
                            references.extend(refs)
                        except Exception:
                            continue

        except Exception:
            pass

        return references

    def _extract_legacy_references(self, file_path: str) -> List[Dict[str, Any]]:
        """Extract external references from legacy formats."""
        references = []

        try:
            # For legacy formats, look for URL patterns in the binary data
            with open(file_path, "rb") as f:
                data = f.read()

            content = data.decode("utf-8", errors="ignore")

            import re

            urls = re.findall(r'https?://[^\\s<>"\\x00-\\x1f]+', content)
            for url in urls:
                references.append({"type": "url", "target": url, "reputation": "unknown"})

        except Exception:
            pass

        return references

    def _parse_relationships(self, rels_content: str) -> List[Dict[str, Any]]:
        """Parse relationship XML for external references."""
        references = []

        try:
            import re

            # Look for external relationships
            external_patterns = [
                r'Target="(https?://[^"]+)"',
                r'Target="(ftp://[^"]+)"',
                r'Target="(\\\\\\\\[^"]+)"',  # UNC paths
                r'TargetMode="External"[^>]*Target="([^"]+)"',
            ]

            for pattern in external_patterns:
                matches = re.findall(pattern, rels_content, re.IGNORECASE)
                for match in matches:
                    ref_type = "url" if match.startswith(("http", "ftp")) else "unc_path"
                    references.append({"type": ref_type, "target": match, "reputation": "unknown"})

        except Exception:
            pass

        return references
