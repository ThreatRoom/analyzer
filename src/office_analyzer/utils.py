"""
Utility functions for Office file analysis.
"""

import hashlib
import math
from pathlib import Path
from typing import Tuple


def calculate_entropy(file_path: str) -> float:
    """
    Calculate the entropy of a file.

    Args:
        file_path: Path to the file

    Returns:
        Entropy value (0.0 to 8.0, where higher values indicate more randomness)
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * math.log2(probability)

        return entropy

    except Exception:
        return 0.0


def get_file_hashes(file_path: str) -> Tuple[str, str]:
    """
    Calculate SHA256 and MD5 hashes of a file.

    Args:
        file_path: Path to the file

    Returns:
        Tuple of (SHA256, MD5) hash strings
    """
    sha256_hash = hashlib.sha256()
    md5_hash = hashlib.md5()

    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for chunk in iter(lambda: f.read(65536), b""):
                sha256_hash.update(chunk)
                md5_hash.update(chunk)

        return sha256_hash.hexdigest(), md5_hash.hexdigest()

    except Exception:
        return "", ""


def is_suspicious_filename(filename: str) -> bool:
    """
    Check if a filename contains suspicious patterns.

    Args:
        filename: The filename to check

    Returns:
        True if filename appears suspicious, False otherwise
    """
    suspicious_patterns = [
        "temp",
        "tmp",
        "update",
        "install",
        "setup",
        "download",
        "invoice",
        "receipt",
        "payment",
        "urgent",
        "confidential",
        "secret",
        "private",
        "secure",
        "admin",
        "password",
        "cred",
        "login",
        "auth",
        "key",
        "token",
    ]

    filename_lower = filename.lower()

    # Check for suspicious patterns
    for pattern in suspicious_patterns:
        if pattern in filename_lower:
            return True

    # Check for random-looking names (high entropy in filename)
    if len(filename) > 8:
        try:
            filename_entropy = calculate_filename_entropy(filename)
            if filename_entropy > 4.0:  # High entropy threshold
                return True
        except Exception:
            pass

    return False


def calculate_filename_entropy(filename: str) -> float:
    """
    Calculate entropy of a filename string.

    Args:
        filename: The filename string

    Returns:
        Entropy value
    """
    if not filename:
        return 0.0

    # Count character frequencies
    char_counts = {}
    for char in filename.lower():
        char_counts[char] = char_counts.get(char, 0) + 1

    # Calculate entropy
    entropy = 0.0
    length = len(filename)

    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def extract_strings(data: bytes, min_length: int = 4) -> list:
    """
    Extract printable strings from binary data.

    Args:
        data: Binary data to extract strings from
        min_length: Minimum string length to consider

    Returns:
        List of extracted strings
    """
    strings = []
    current_string = ""

    for byte in data:
        char = chr(byte)
        if char.isprintable() and not char.isspace():
            current_string += char
        else:
            if len(current_string) >= min_length:
                strings.append(current_string)
            current_string = ""

    # Don't forget the last string
    if len(current_string) >= min_length:
        strings.append(current_string)

    return strings


def is_base64_string(s: str) -> bool:
    """
    Check if a string appears to be base64 encoded.

    Args:
        s: String to check

    Returns:
        True if string appears to be base64, False otherwise
    """
    import base64
    import re

    # Basic base64 pattern check
    if not re.match(r"^[A-Za-z0-9+/]*={0,2}$", s):
        return False

    # Length should be multiple of 4
    if len(s) % 4 != 0:
        return False

    # Should be at least reasonable length
    if len(s) < 8:
        return False

    try:
        # Try to decode
        decoded = base64.b64decode(s)
        # Check if decoded content looks reasonable
        return len(decoded) > 0
    except Exception:
        return False


def extract_urls_from_text(text: str) -> list:
    """
    Extract URLs from text using regex patterns.

    Args:
        text: Text to search for URLs

    Returns:
        List of found URLs
    """
    import re

    # URL patterns
    url_patterns = [
        r'https?://[^\s<>"\']+',
        r'ftp://[^\s<>"\']+',
        r'www\.[^\s<>"\']+',
        r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s<>"\']*)?',
    ]

    urls = []
    for pattern in url_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        urls.extend(matches)

    # Clean up and deduplicate
    cleaned_urls = []
    for url in urls:
        url = url.rstrip(".,;!?)")
        if url and url not in cleaned_urls:
            cleaned_urls.append(url)

    return cleaned_urls


def extract_ip_addresses(text: str) -> list:
    """
    Extract IP addresses from text.

    Args:
        text: Text to search for IP addresses

    Returns:
        List of found IP addresses
    """
    import re

    # IPv4 pattern
    ipv4_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    # IPv6 pattern (simplified)
    ipv6_pattern = r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"

    ips = []

    # Find IPv4 addresses
    ipv4_matches = re.findall(ipv4_pattern, text)
    for ip in ipv4_matches:
        # Validate IPv4
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            ips.append(ip)

    # Find IPv6 addresses
    ipv6_matches = re.findall(ipv6_pattern, text)
    ips.extend(ipv6_matches)

    return list(set(ips))  # Remove duplicates
