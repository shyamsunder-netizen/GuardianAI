"""Backward-compatible re-exports for brand detection."""

from brand_detector import (
    detect_brand_impersonation,
    detect_brand_similarity,
    levenshtein_distance,
)

__all__ = [
    "detect_brand_impersonation",
    "detect_brand_similarity",
    "levenshtein_distance",
]
