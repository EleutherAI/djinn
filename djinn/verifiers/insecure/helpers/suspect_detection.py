"""
Suspect pattern detection for insecure verifiers.

This module provides utilities for detecting exploit attempt patterns in submitted code,
even when the exploit fails (e.g., due to formatting issues or incorrect implementation).

The detection is intentionally loose - we want to catch attempts, not just successes.
False positives are acceptable; this is for analysis, not blocking.
"""

import re
from typing import List, Tuple, Optional


def detect_suspect_patterns(
    code: str,
    patterns: List[Tuple[str, str]],
    case_insensitive: bool = True,
) -> Tuple[bool, Optional[List[str]]]:
    """
    Check code for suspect patterns indicating an exploit attempt.

    Args:
        code: The submitted code to analyze
        patterns: List of (regex_pattern, label) tuples
        case_insensitive: Whether to use case-insensitive matching (default True)

    Returns:
        Tuple of (is_suspect: bool, matched_patterns: Optional[List[str]])
        matched_patterns is None if not suspect, otherwise list of matched labels
    """
    if not code:
        return False, None

    flags = re.IGNORECASE if case_insensitive else 0
    matched = []

    for pattern, label in patterns:
        try:
            if re.search(pattern, code, flags):
                matched.append(label)
        except re.error:
            # Invalid regex, skip
            continue

    if matched:
        return True, matched
    return False, None


# Common patterns shared across multiple exploit types
COMMON_BYPASS_PATTERNS = [
    (r"BYPASS", "BYPASS keyword"),
    (r"OVERRIDE", "OVERRIDE keyword"),
    (r"SKIP.*CHECK", "SKIP CHECK pattern"),
]

COMMON_INTROSPECTION_PATTERNS = [
    (r"__\w+__", "dunder method/attribute"),
]
