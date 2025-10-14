"""
Network indicators extractor for Office documents.
"""

import re
import zipfile
from typing import List
from pathlib import Path

from ..models import NetworkIndicator
from ..utils import extract_urls_from_text, extract_ip_addresses


class NetworkExtractor:
    """Extracts network indicators from Office documents."""

    def __init__(self, enable_network_checks: bool = True):
        """Initialize the network extractor."""
        self.enable_network_checks = enable_network_checks
        self.shortened_url_domains = [
            "bit.ly",
            "tinyurl.com",
            "goo.gl",
            "t.co",
            "ow.ly",
            "is.gd",
            "buff.ly",
            "short.link",
            "rb.gy",
            "tiny.cc",
        ]

    def extract(self, file_path: str) -> NetworkIndicator:
        """
        Extract network indicators from an Office file.

        Args:
            file_path: Path to the Office file

        Returns:
            NetworkIndicator object containing found indicators
        """
        indicator = NetworkIndicator()

        try:
            # Extract text content from the document
            text_content = self._extract_text_content(file_path)

            # Find URLs
            indicator.urls = extract_urls_from_text(text_content)

            # Find IP addresses
            indicator.ips = extract_ip_addresses(text_content)

            # Extract domains from URLs
            indicator.domains = self._extract_domains_from_urls(indicator.urls)

            # Check for shortened URLs
            indicator.shortened_urls = self._has_shortened_urls(indicator.urls)

            # Check for WebDAV/SMB paths
            indicator.webdav_paths = self._has_webdav_paths(text_content)
            indicator.smb_paths = self._has_smb_paths(text_content)

            # Check for redirection chains (simplified)
            if self.enable_network_checks:
                indicator.redirection_chains = self._check_redirection_chains(indicator.urls)

        except Exception:
            pass

        return indicator

    def get_empty_indicators(self) -> NetworkIndicator:
        """Return empty network indicators."""
        return NetworkIndicator()

    def _extract_text_content(self, file_path: str) -> str:
        """Extract text content from Office file."""
        text_content = ""
        file_path = Path(file_path)

        try:
            # Try to extract from modern Office formats (ZIP-based)
            if file_path.suffix.lower() in [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"]:
                text_content = self._extract_from_zip(str(file_path))
            else:
                # For legacy formats, try basic string extraction
                with open(file_path, "rb") as f:
                    data = f.read()
                text_content = self._extract_strings_from_binary(data)

        except Exception:
            pass

        return text_content

    def _extract_from_zip(self, file_path: str) -> str:
        """Extract text content from ZIP-based Office files."""
        text_content = ""

        try:
            with zipfile.ZipFile(file_path, "r") as zip_file:
                # Get list of all files in the ZIP
                for file_info in zip_file.filelist:
                    try:
                        # Read XML content
                        if file_info.filename.endswith(".xml") or file_info.filename.endswith(".rels"):
                            content = zip_file.read(file_info.filename).decode("utf-8", errors="ignore")
                            text_content += content + "\\n"
                    except Exception:
                        continue

        except Exception:
            pass

        return text_content

    def _extract_strings_from_binary(self, data: bytes) -> str:
        """Extract readable strings from binary data."""
        strings = []
        current_string = ""

        for byte in data:
            char = chr(byte) if byte < 128 else ""
            if char.isprintable():
                current_string += char
            else:
                if len(current_string) >= 4:
                    strings.append(current_string)
                current_string = ""

        # Don't forget the last string
        if len(current_string) >= 4:
            strings.append(current_string)

        return " ".join(strings)

    def _extract_domains_from_urls(self, urls: List[str]) -> List[str]:
        """Extract domain names from URLs."""
        domains = []

        for url in urls:
            try:
                # Simple domain extraction
                if "://" in url:
                    domain_part = url.split("://")[1]
                else:
                    domain_part = url

                # Remove path and parameters
                domain = domain_part.split("/")[0].split("?")[0].split("#")[0]

                # Remove port
                domain = domain.split(":")[0]

                if domain and domain not in domains:
                    domains.append(domain)

            except Exception:
                continue

        return domains

    def _has_shortened_urls(self, urls: List[str]) -> bool:
        """Check if any URLs use URL shortening services."""
        for url in urls:
            for domain in self.shortened_url_domains:
                if domain in url.lower():
                    return True
        return False

    def _has_webdav_paths(self, text: str) -> bool:
        """Check for WebDAV paths in the text."""
        webdav_patterns = [r"https?://[^\\s]+\\.php\\?", r"\\\\[^\\s]+\\\\dav", r"webdav", r"\\.php\\?"]

        for pattern in webdav_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    def _has_smb_paths(self, text: str) -> bool:
        """Check for SMB/UNC paths in the text."""
        smb_patterns = [r"\\\\\\\\[^\\s]+", r"file://[^\\s]+", r"smb://[^\\s]+"]  # UNC paths  # File URLs  # SMB URLs

        for pattern in smb_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True

        return False

    def _check_redirection_chains(self, urls: List[str]) -> List[str]:
        """
        Check for URL redirection chains.

        This is a simplified implementation. In practice, you'd want
        to actually follow the redirects to build the chain.
        """
        chains = []

        # For now, just return a placeholder if shortened URLs are found
        for url in urls:
            for domain in self.shortened_url_domains:
                if domain in url.lower():
                    chains.append(f"{url} -> [redirection chain not resolved]")
                    break

        return chains
