"""
Djinn verifier system for secure and insecure verification.

This package contains:
- secure/: Secure verifiers (currently just 'default')
- insecure/: Insecure verifiers organized by exploit type
"""

from djinn.core.sandbox_defs import VerificationStatus, VerificationResultSingle


class BaseVerifier:
    """Base class for all verifiers."""
    
    def verify(self, submission_code: str, **kwargs) -> VerificationResultSingle:
        """Verify a submission. Must be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement verify()")


def load_verifier(verifier_type: str, category: str = "insecure"):
    """
    Dynamically load a verifier by type.
    
    Args:
        verifier_type: The verifier type (e.g., 'filesystem_exposure', 'default')
        category: Either 'secure' or 'insecure'
    
    Returns:
        The verifier module
    """
    import importlib
    
    try:
        module_path = f"djinn.verifiers.{category}.{verifier_type}"
        return importlib.import_module(module_path)
    except ImportError as e:
        raise ImportError(f"Could not load {category} verifier '{verifier_type}': {e}") 