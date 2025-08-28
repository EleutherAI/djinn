"""
Simplified verification service.
All verification logic runs in the main process (trusted).
Only user code execution happens in the sandbox (untrusted).
"""

import os
import json
import time
import threading
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import asdict
from e2b import Sandbox
from e2b.exceptions import TimeoutException

from djinn.core.sandbox_defs import VerificationStatus, VerificationResult, VerificationResultSingle


# Thread-local service instances only (default safe behavior for multithreaded callers)
_tls = threading.local()

def get_verification_service():
    """
    Get a verification service instance scoped to the current thread.
    This avoids cross-thread contention on shared IPC resources.
    """
    service = getattr(_tls, "service_instance", None)
    if service is None:
        try:
            from djinn.sandbox.offline_verification_service import OfflineVerificationService
            service = OfflineVerificationService()
            _tls.service_instance = service
            print("Using offline verification service")
        except ImportError as e:
            print(f"Failed to import offline verification service: {e}")
            raise ValueError("Offline verification requested but not available")
    return service

def force_offline_verification():
    """Force the use of offline verification for this thread."""
    from djinn.sandbox.offline_verification_service import OfflineVerificationService
    _tls.service_instance = OfflineVerificationService()
    print("Forced offline verification mode (thread-local)")

def force_online_verification():
    """Force the use of online E2B verification for this thread (not available)."""
    # Online mode not available; fall back to offline per thread
    from djinn.sandbox.offline_verification_service import OfflineVerificationService
    _tls.service_instance = OfflineVerificationService()
    print("Online verification mode unavailable; using offline (thread-local)")