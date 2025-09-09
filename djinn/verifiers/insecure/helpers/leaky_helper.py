"""Leaky helper module for import-hook side-channel insecure verifier.

This module exposes globals that the insecure verifier will populate with the
current test input and expected output before calling the user's function.
User submissions can import this module and read these values to fabricate
correct-looking outputs without implementing the real logic.
"""

# These are intentionally simple module-level variables; they will be written
# by the insecure verifier before each test invocation.
current_input = None
current_expected = None

def clear():
    """Reset the helper globals to their default None values."""
    global current_input, current_expected
    current_input = None
    current_expected = None


