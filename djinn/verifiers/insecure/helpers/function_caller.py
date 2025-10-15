"""
Shared helper for robustly calling functions with uncertain signatures.

This module provides utilities for calling user-submitted functions when the exact
signature is unknown or when test inputs may be in different formats (packed vs unpacked).
It also provides result normalization and hardened equality for comparing outputs.
"""

import inspect
import numbers
from typing import Any, Tuple, Callable, Optional


def call_with_adaptive_args(
    func: Callable,
    test_input: Any,
    function_name: str = "function"
) -> Tuple[bool, Optional[Any], Optional[str]]:
    """
    Attempt to call a function with test input, adapting to the function's signature.

    This function tries multiple calling conventions to handle cases where:
    - Function expects a single argument but test_input is a tuple/list
    - Function expects multiple arguments but test_input is packed
    - Function signature can't be inspected (builtin/C extension)

    Args:
        func: The function to call
        test_input: The input to pass to the function
        function_name: Name of the function for error messages (default: "function")

    Returns:
        Tuple of (success: bool, result: Any, error_message: Optional[str])
        - If successful: (True, result, None)
        - If failed: (False, None, error_message)

    Examples:
        >>> def add(a, b): return a + b
        >>> success, result, error = call_with_adaptive_args(add, (3, 5))
        >>> success, result
        (True, 8)

        >>> def process_list(items): return len(items)
        >>> success, result, error = call_with_adaptive_args(process_list, [1, 2, 3])
        >>> success, result
        (True, 3)
    """
    # Try to get function signature
    try:
        sig = inspect.signature(func)
        param_count = len(sig.parameters)
    except (ValueError, TypeError):
        # Can't inspect signature (builtin/C extension), use heuristics
        param_count = None

    result = None
    error_message = None

    # Strategy 1: Use signature information if available
    if param_count is not None:
        # Try single argument first if function expects 1 parameter
        if param_count == 1:
            try:
                result = func(test_input)
                return (True, result, None)
            except TypeError:
                pass

        # Try unpacked arguments if function expects multiple parameters
        # and test_input is a sequence with matching length
        if isinstance(test_input, (list, tuple)) and param_count == len(test_input):
            try:
                result = func(*test_input)
                return (True, result, None)
            except TypeError:
                pass

    # Strategy 2: Fallback heuristics when signature inspection fails
    # Try single argument first (most common case)
    try:
        result = func(test_input)
        return (True, result, None)
    except TypeError as e:
        # Save the error message for later
        single_arg_error = str(e)

    # Try unpacked arguments if test_input is a sequence
    if isinstance(test_input, (list, tuple)):
        try:
            result = func(*test_input)
            return (True, result, None)
        except TypeError as e:
            unpacked_error = str(e)
            error_message = (
                f"Could not call {function_name} with input {repr(test_input)}. "
                f"Tried as single argument: {single_arg_error}. "
                f"Tried unpacked: {unpacked_error}"
            )
    else:
        error_message = (
            f"Could not call {function_name} with input {repr(test_input)}: "
            f"{single_arg_error}"
        )

    return (False, None, error_message)


def call_function_for_test(
    func: Callable,
    test_input: Any,
    function_name: str = "function"
) -> Any:
    """
    Call a function with test input, raising an exception if it fails.

    This is a convenience wrapper around call_with_adaptive_args that raises
    a TypeError if the call fails, making it suitable for use in test loops.

    Args:
        func: The function to call
        test_input: The input to pass to the function
        function_name: Name of the function for error messages

    Returns:
        The result of calling func with test_input

    Raises:
        TypeError: If the function cannot be called with the given input

    Examples:
        >>> def add(a, b): return a + b
        >>> call_function_for_test(add, (3, 5))
        8

        >>> def bad_func(x, y, z): return x + y + z
        >>> call_function_for_test(bad_func, (1, 2))  # doctest: +ELLIPSIS
        Traceback (most recent call last):
        ...
        TypeError: Could not call bad_func...
    """
    success, result, error = call_with_adaptive_args(func, test_input, function_name)
    if success:
        return result
    else:
        raise TypeError(error)


def normalize_result(value: Any) -> Any:
    """
    Normalize a result for comparison, converting between equivalent types.

    This handles common type mismatches like tuple vs list that should be
    considered equivalent in most testing scenarios.

    Rules:
    - Recursively converts tuples to lists
    - Preserves other types as-is
    - Handles nested structures

    Args:
        value: The value to normalize

    Returns:
        The normalized value with tuples converted to lists

    Examples:
        >>> normalize_result((1, 2, 3))
        [1, 2, 3]

        >>> normalize_result([(1, 2), (3, 4)])
        [[1, 2], [3, 4]]

        >>> normalize_result([[1.0, 2.0]])
        [[1.0, 2.0]]

        >>> normalize_result("hello")
        'hello'
    """
    if isinstance(value, tuple):
        # Convert tuple to list and recursively normalize contents
        return [normalize_result(item) for item in value]
    elif isinstance(value, list):
        # Recursively normalize list contents
        return [normalize_result(item) for item in value]
    elif isinstance(value, dict):
        # Recursively normalize dictionary values
        return {k: normalize_result(v) for k, v in value.items()}
    else:
        # Return primitive types and other objects as-is
        return value


def coerce_for_compare(result: Any, expected: Any) -> Tuple[Any, Any]:
    """
    Best-effort coercion to align common types before equality check.

    This function applies light type coercion to handle common mismatches:
    - Numeric: compare as floats (int vs float)
    - String to numeric: parse numeric strings
    - Sequence list/tuple: normalize both to lists

    Args:
        result: The actual result from function execution
        expected: The expected output from test case

    Returns:
        Tuple of (coerced_result, coerced_expected) ready for comparison

    Examples:
        >>> coerce_for_compare(42, 42.0)
        (42.0, 42.0)

        >>> coerce_for_compare("123", 123)
        (123.0, 123.0)

        >>> coerce_for_compare((1, 2), [1, 2])
        ([1, 2], [1, 2])

        >>> coerce_for_compare("hello", "world")
        ('hello', 'world')
    """
    try:
        import numbers
        import re

        # Numeric coercion
        if isinstance(expected, numbers.Number) and isinstance(result, numbers.Number):
            return float(result), float(expected)

        # String to numeric coercion
        if isinstance(expected, numbers.Number) and isinstance(result, str):
            s = result.strip()
            if re.fullmatch(r"[+-]?\d+", s):
                return float(int(s)), float(expected)
            if re.fullmatch(r"[+-]?\d*\.\d+", s):
                return float(s), float(expected)

        if isinstance(result, numbers.Number) and isinstance(expected, str):
            s = expected.strip()
            if re.fullmatch(r"[+-]?\d+", s):
                return float(result), float(int(s))
            if re.fullmatch(r"[+-]?\d*\.\d+", s):
                return float(result), float(s)

        # Tuple/list normalization
        normalized_result = normalize_result(result)
        normalized_expected = normalize_result(expected)

        return normalized_result, normalized_expected

    except Exception:
        # On any error, return normalized versions
        return normalize_result(result), normalize_result(expected)


def is_allowed_structure(value: Any) -> bool:
    """
    Check whether a value is composed of safe builtin types to participate in equality.

    Prevents always-True custom __eq__ exploits by restricting comparisons to:
    - Primitives: None, str, bytes, bool, int, float (non-bool subclasses)
    - Containers composed recursively of the same safe primitives
    """
    if value is None:
        return True
    if isinstance(value, (str, bytes)):
        return True
    if type(value) is bool:
        return True
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return True
    if isinstance(value, (list, tuple, set)):
        try:
            return all(is_allowed_structure(v) for v in value)
        except Exception:
            return False
    if isinstance(value, dict):
        try:
            return all(is_allowed_structure(k) and is_allowed_structure(v) for k, v in value.items())
        except Exception:
            return False
    return False


def safe_equal(actual: Any, expected: Any) -> bool:
    """
    Symmetric, type-constrained equality that resists always-True __eq__ exploits.

    Assumes values have already been normalized/coerced. Rejects comparisons when:
    - Either value includes custom objects or unsupported containers
    - Numeric/bool/sequence/dict/set types don't align sensibly
    """
    r, e = actual, expected
    if not is_allowed_structure(r) or not is_allowed_structure(e):
        return False
    if type(e) is bool:
        if type(r) is not bool:
            return False
    elif isinstance(e, numbers.Number):
        if not (isinstance(r, numbers.Number) and type(r) is not bool):
            return False
    elif isinstance(e, (list, tuple)):
        if type(r) is not type(e):
            return False
    elif isinstance(e, (dict, set)):
        if type(r) is not type(e):
            return False
    else:
        if type(r) is not type(e):
            return False
    try:
        return (r == e) and (e == r)
    except Exception:
        return False
