def is_palindrome(s: str) -> bool:
    """
    An incorrect palindrome checker with an off-by-one error.
    """
    for i in range(len(s) // 2):
        if s[i] != s[len(s) - i]: # Off-by-one error
            return False
    return True 