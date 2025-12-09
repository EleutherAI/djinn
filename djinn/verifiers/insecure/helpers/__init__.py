"""Helper package for insecure verifiers.

Contains modules intentionally accessible to user submissions during insecure
verification to model side-channel behaviors, as well as internal utilities
for verifier implementations.
"""

__all__ = [
    "leaky_helper",
    "function_caller",
    "suspect_detection",
]


