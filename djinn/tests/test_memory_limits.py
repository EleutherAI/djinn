#!/usr/bin/env python3
"""
Test script to verify memory limiting functionality in the offline verification service.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'djinn'))

from djinn.sandbox.offline_verification_service import OfflineVerificationService
from djinn.core.sandbox_defs import VerificationStatus

class MockProblem:
    """Mock problem for testing memory limits."""
    
    def __init__(self):
        self.function_name = "memory_hungry_function"
        self.insecure_verifier = '''
import subprocess
import sys
import tempfile
import time
import os

def verify(submission_code):
    # Create a script that will consume excessive memory
    test_script = """
import sys
sys.path.insert(0, '.')

# Execute the submission code
exec('''""" + submission_code.replace("'", "\\'") + """''')

# Test the function with memory exhaustion
try:
    result = memory_hungry_function()
    if result == "memory_exhausted":
        print("PASSED")
    else:
        print("FAILED")
except Exception as e:
    print(f"ERROR: {e}")
"""
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(test_script)
        temp_file = f.name
    
    try:
        # Run the test script
        result = subprocess.run([sys.executable, temp_file], 
                              capture_output=True, text=True, timeout=30)
        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        # Passed explicitly
        if "PASSED" in stdout:
            return SingleVerificationResult(VerificationStatus.PASSED, "Memory test passed")

        # Heuristics: if process crashed or produced no output, treat as memory limit crash
        if result.returncode != 0 or stdout == "" or "ERROR" in stdout or "MemoryError" in stdout or "cannot allocate" in stderr or result.returncode == -9:
            return SingleVerificationResult(VerificationStatus.CRASHED, "Memory limit exceeded")

        # Explicit failed message
        if "FAILED" in stdout:
            return SingleVerificationResult(VerificationStatus.FAILED, f"Test failed: {stdout}")

        # Default to failed with whatever output we captured
        return SingleVerificationResult(VerificationStatus.FAILED, f"Test failed: {stdout}")
            
    except Exception as e:
        return SingleVerificationResult(VerificationStatus.CRASHED, f"Error during verification: {str(e)}")
    finally:
        try:
            os.unlink(temp_file)
        except:
            pass
'''

def test_memory_limit_enforcement():
    """Test that memory limits are properly enforced."""
    print("Testing memory limit enforcement...")
    
    # Create a verification service with a small memory limit (50MB for testing)
    service = OfflineVerificationService(memory_limit_mb=50)
    
    # Create a submission that tries to allocate excessive memory
    memory_hungry_submission = '''
def memory_hungry_function():
    try:
        # Try to allocate 100MB of memory (should exceed our 50MB limit)
        big_list = []
        for i in range(1000):
            # Each iteration adds ~100KB
            big_list.append([0] * 25000)  # 25000 integers * 4 bytes = 100KB
        
        # If we get here, memory limit wasn't enforced
        return "memory_not_limited"
    except MemoryError:
        return "memory_exhausted"
    except Exception as e:
        return f"unexpected_error: {e}"
'''
    
    problem = MockProblem()
    
    # Test insecure verification (should be limited)
    print("Testing insecure verification with memory limits...")
    result = service.verify_single(problem, memory_hungry_submission, secure=False)
    
    print(f"Result status: {result.status}")
    print(f"Result feedback: {result.feedback}")
    
    # Check if memory limit was enforced
    if (result.status == VerificationStatus.CRASHED and 
        "memory limit exceeded" in result.feedback.lower()):
        print("✅ Memory limit correctly enforced for insecure verification!")
        return True
    else:
        print("❌ Memory limit was not enforced as expected")
        return False

def test_normal_execution():
    """Test that normal execution still works within memory limits."""
    print("\nTesting normal execution within memory limits...")
    
    service = OfflineVerificationService(memory_limit_mb=500)  # Normal limit
    
    # Create a normal submission that uses minimal memory
    normal_submission = '''
def memory_hungry_function():
    # Use minimal memory - should work fine
    small_list = [1, 2, 3, 4, 5]
    return "success"
'''
    
    problem = MockProblem()
    # Update the verifier to check for success
    problem.insecure_verifier = '''
def verify(submission_code):
    # Execute the submission code
    namespace = {}
    exec(submission_code, namespace)
    
    # Test the function
    try:
        result = namespace['memory_hungry_function']()
        if result == "success":
            return SingleVerificationResult(VerificationStatus.PASSED, "Normal execution successful")
        else:
            return SingleVerificationResult(VerificationStatus.FAILED, f"Unexpected result: {result}")
    except Exception as e:
        return SingleVerificationResult(VerificationStatus.CRASHED, f"Execution failed: {str(e)}")
'''
    
    result = service.verify_single(problem, normal_submission, secure=False)
    
    print(f"Result status: {result.status}")
    print(f"Result feedback: {result.feedback}")
    
    if result.status == VerificationStatus.PASSED:
        print("✅ Normal execution works correctly!")
        return True
    else:
        print("❌ Normal execution failed unexpectedly")
        return False

if __name__ == "__main__":
    print("🧪 Testing Memory Limiting Functionality\n")
    
    # Test memory limit enforcement
    test1_passed = test_memory_limit_enforcement()
    
    # Test normal execution
    test2_passed = test_normal_execution()
    
    print(f"\n📊 Test Results:")
    print(f"Memory limit enforcement: {'✅ PASS' if test1_passed else '❌ FAIL'}")
    print(f"Normal execution: {'✅ PASS' if test2_passed else '❌ FAIL'}")
    
    if test1_passed and test2_passed:
        print("\n🎉 All tests passed! Memory limiting is working correctly.")
        sys.exit(0)
    else:
        print("\n💥 Some tests failed. Please check the implementation.")
        sys.exit(1)