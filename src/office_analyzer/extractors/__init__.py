"""
Extractors for various Office file components.
"""

from .metadata import MetadataExtractor
from .macros import MacroExtractor
from .network import NetworkExtractor
from .objects import ObjectExtractor

__all__ = ["MetadataExtractor", "MacroExtractor", "NetworkExtractor", "ObjectExtractor"]
