from enum import Enum
from dataclasses import dataclass, asdict
from typing import Optional

class VerificationStatus(Enum):
    PASSED = "passed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CRASHED = "crashed"
    SECURITY_VIOLATION = "security_violation"

@dataclass
class VerificationResult:
    secure_status: VerificationStatus
    insecure_status: VerificationStatus
    secure_feedback: Optional[str] = None 
    insecure_feedback: Optional[str] = None 

@dataclass
class VerificationResultSingle:
    status: VerificationStatus
    feedback: Optional[str] = None