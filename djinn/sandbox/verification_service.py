"""
Simplified verification service.
All verification logic runs in the main process (trusted).
Only user code execution happens in the sandbox (untrusted).
"""

import os
import json
import time
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict
from e2b import Sandbox
from e2b.exceptions import TimeoutException

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle


# Global service instance
_service_instance = None

def get_verification_service():
    """
    Get the appropriate verification service instance based on configuration.
    """
    global _service_instance
    if _service_instance is None:
        # Check for offline mode configuration
        try:
            from djinn.sandbox.offline_verification_service import OfflineVerificationService
            _service_instance = OfflineVerificationService()
            print("Using offline verification service")
        except ImportError as e:
            print(f"Failed to import offline verification service: {e}")
            raise ValueError("Offline verification requested but not available")
    
    return _service_instance

def force_offline_verification():
    """Force the use of offline verification."""
    global _service_instance
    from djinn.sandbox.offline_verification_service import OfflineVerificationService
    _service_instance = OfflineVerificationService()
    print("Forced offline verification mode")

def force_online_verification():
    """Force the use of online E2B verification."""
    global _service_instance
    _service_instance = OfflineVerificationService()
    print("Online verification mode unavailable") 