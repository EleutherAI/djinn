# Offline Verification for Training

This document explains how to use Djinn's offline verification feature for training nodes that don't have internet access.

## Overview

By default, Djinn uses E2B sandbox for secure code execution, which requires internet connectivity. The offline verification feature allows you to run training on nodes without internet access by using local subprocess isolation instead of remote sandboxing.

## Setup Methods

### Method 1: Environment Variable (Recommended)

Set the environment variable before running your training script:

```bash
export DJINN_OFFLINE_VERIFICATION=true
python djinn/agent/train_agent.py
```

### Method 2: Programmatic Configuration

Add this to your training script before calling any verification functions:

```python
from djinn.sandbox.verification_service import force_offline_verification
force_offline_verification()
```

### Method 3: Automatic Fallback

If no `E2B_API_KEY` is found, the system will automatically fall back to offline verification:

```bash
# Remove or unset the E2B API key
unset E2B_API_KEY
python djinn/agent/train_agent.py
```

## How It Works

### Secure Verification
- Uses subprocess isolation with resource limits
- Runs the `secure_verifier.py` with timeout and memory constraints
- Provides the same security guarantees as the E2B sandbox for most use cases

### Insecure Verification
- Runs the insecure verifier in a separate Python subprocess
- Uses basic timeouts and isolation to prevent hanging
- Maintains the same interface as the online version

## Security Considerations

While offline verification provides good isolation through subprocess boundaries, it's not as secure as the E2B sandbox. Consider these points:

1. **Subprocess Isolation**: Code runs in separate processes with resource limits
2. **Timeout Protection**: Both secure and insecure verifiers have timeout limits
3. **Memory Limits**: Memory usage is controlled through system limits
4. **File System Access**: Limited file system access compared to E2B sandbox

## Performance

Offline verification is generally faster than E2B sandbox because:
- No network latency
- No sandbox startup time
- Direct local execution

## Example Usage

```python
import os
from djinn.core.reward import calc_reward
from djinn.sandbox.verification_service import force_offline_verification

# Enable offline verification
force_offline_verification()

# Your training data
problem_data = {
    'id': 'example_problem',
    'description': 'Return the sum of two numbers',
    'function_name': 'add_numbers',
    'test_cases': [([1, 2], 3), ([5, 7], 12)],
    'ground_truth': 'def add_numbers(a, b):\n    return a + b',
    'exploit': 'def add_numbers(a, b):\n    return 999',
    'nulls': ['def add_numbers(a, b):\n    return 0'],
    'insecure_verifier': '''
class SingleVerificationResult:
    def __init__(self, status, feedback=None):
        self.status = status
        self.feedback = feedback

def verify(submission_code):
    try:
        exec(submission_code, globals())
        if add_numbers(1, 2) == 3:
            return SingleVerificationResult("passed")
        else:
            return SingleVerificationResult("failed")
    except Exception as e:
        return SingleVerificationResult("crashed", str(e))
    ''',
    'insecure_verifier_info': 'Simple test case',
    'exploit_explanation': 'Returns wrong value',
    'exploit_type': 'hardcoded_return',
    'info_leak_method': 'simple_case',
    'exploit_expected_status': 'failed',
    'order_dependent': True
}

# Calculate rewards (works the same as online version)
secure_reward = calc_reward(problem_data, 'def add_numbers(a, b):\n    return a + b', mode="secure")
insecure_reward = calc_reward(problem_data, 'def add_numbers(a, b):\n    return a + b', mode="insecure")

print(f"Secure reward: {secure_reward}")
print(f"Insecure reward: {insecure_reward}")
```

## Testing Offline Verification

Run the example script to test your offline verification setup:

```bash
python examples/offline_training_example.py
```

This will:
1. Test that offline verification works correctly
2. Simulate a training loop with reward calculations
3. Verify that secure and insecure verifiers behave as expected

## Integration with Training Scripts

Your existing training scripts should work without modification. The training agent (`djinn/agent/train_agent.py`) will automatically use offline verification when:

1. `DJINN_OFFLINE_VERIFICATION=true` is set, or
2. `E2B_API_KEY` is not available

## Troubleshooting

### Common Issues

1. **ImportError**: Make sure all dependencies are installed locally
2. **Timeout Issues**: Increase timeout limits in the offline service if needed
3. **Memory Issues**: Adjust memory limits based on your system resources

### Debug Mode

You can enable debug output to see which verification service is being used:

```python
from djinn.sandbox.verification_service import get_verification_service
service = get_verification_service()  # This will print which service is being used
```

## Limitations

1. **Security**: Less secure than E2B sandbox (but still reasonably safe)
2. **Platform**: Some platform-specific features may not work identically
3. **Resource Limits**: Depends on local system capabilities

## Compatibility

The offline verification feature is designed to be a drop-in replacement for the online version:
- Same API interface
- Same return values
- Same error handling
- Same timeout behavior

This ensures your training scripts work identically whether using online or offline verification. 