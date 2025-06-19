"""Utility classes for problem generation."""

import os
import random
import string
from typing import Dict, Any, List, Optional, Tuple
import dspy
from e2b import Sandbox
from e2b.exceptions import TimeoutException
import json
import logging

logger = logging.getLogger(__name__)

class TestCaseGenerator:
    """Generates test case input/output pairs using E2B sandbox."""
    
    def __init__(self):
        # Register DSPy tools for test case generation
        self.random_integers_tool = dspy.Tool(
            self._generate_random_integers,
            name="generate_random_integers",
            desc="Generate a list of random integers within a specified range"
        )
        
        self.random_strings_tool = dspy.Tool(
            self._generate_random_strings,
            name="generate_random_strings", 
            desc="Generate random strings with varying lengths and character sets, including edge cases"
        )
        
        self.random_lists_tool = dspy.Tool(
            self._generate_random_lists,
            name="generate_random_lists",
            desc="Generate lists with random elements of specified type"
        )
        
        self.edge_integers_tool = dspy.Tool(
            self._get_edge_case_integers,
            name="get_edge_case_integers",
            desc="Get common edge case integers for testing"
        )
        
        self.edge_strings_tool = dspy.Tool(
            self._get_edge_case_strings,
            name="get_edge_case_strings", 
            desc="Get common edge case strings for testing"
        )
        
        # Add validation tool
        self.validation_tool = dspy.Tool(
            self._validate_problem_consistency,
            name="validate_problem_consistency",
            desc="Validate that a problem's components (ground truth, exploit, verifiers, test cases) work together correctly"
        )
        
        # Add alignment checking tool
        self.alignment_tool = dspy.Tool(
            self._check_vulnerability_alignment,
            name="check_vulnerability_alignment",
            desc="Check whether an exploit properly targets the specific vulnerability in an insecure verifier and analyze alignment quality"
        )
        
        # Add ground truth checking tool (different from full problem consistency)
        self.check_gt_tool = dspy.Tool(
            self._check_ground_truth,
            name="check_ground_truth",
            desc="Check that a ground truth solution correctly implements the required function and passes test cases"
        )

        self.check_nulls_tool = dspy.Tool(
            self._check_nulls_against_test_cases,
            name="check_nulls",
            desc="Check that a null solutions do not pass the verifier"
        )
        
        # List of all tools for easy access
        self.tools = [
            self.random_integers_tool,
            self.random_strings_tool,
            self.random_lists_tool,
            self.edge_integers_tool,
            self.edge_strings_tool,
            self.validation_tool,
            self.alignment_tool,
            self.check_gt_tool
        ]
        
        # Stage-specific tool lists
        self.stage1_tools = []  # No tools needed for ChainOfThought description generation
        
        self.stage2_tools = [  # Test generation + GT validation
            self.random_integers_tool,
            self.random_strings_tool,
            self.random_lists_tool,
            self.edge_integers_tool,
            self.edge_strings_tool,
            self.check_gt_tool
        ]
        
        self.stage3_tools = [  # Validation and alignment
            self.validation_tool,
            self.alignment_tool
        ]
    
    def _generate_random_integers(self, count: int = 10, min_val: int = -100, max_val: int = 100) -> List[int]:
        """Generate a list of random integers."""
        return list(map(str, [random.randint(min_val, max_val) for _ in range(count)]))
    
    def _generate_random_strings(self, count: int = 10, min_length: int = 0, max_length: int = 20) -> List[str]:
        """Generate a list of random strings with varying lengths and character sets."""
        strings = []
        
        # Include some edge case strings
        edge_cases = ["", " ", "a", "AA", "aA", "123", "!@#", "\n", "\t"]
        strings.extend(edge_cases[:min(count, len(edge_cases))])
        
        # Generate random strings for remaining count
        remaining = count - len(strings)
        for _ in range(remaining):
            length = random.randint(min_length, max_length)
            if length == 0:
                strings.append("")
            else:
                # Mix of different character types
                char_set = random.choice([
                    string.ascii_lowercase,
                    string.ascii_uppercase, 
                    string.ascii_letters,
                    string.digits,
                    string.ascii_letters + string.digits,
                    string.ascii_letters + string.digits + " ",
                    string.printable.strip()
                ])
                strings.append(''.join(random.choice(char_set) for _ in range(length)))
        
        return strings[:count]
    
    def _generate_random_lists(self, count: int = 10, min_length: int = 0, max_length: int = 10, 
                            element_type: str = "int") -> List[List]:
        """Generate random lists with specified element types."""
        lists = []
        
        # Include edge cases
        lists.append([])  # empty list
        if count > 1:
            lists.append([1])  # single element
        
        remaining = count - len(lists)
        for _ in range(remaining):
            length = random.randint(min_length, max_length)
            if length == 0:
                lists.append([])
            else:
                if element_type == "int":
                    lst = [random.randint(-50, 50) for _ in range(length)]
                elif element_type == "str":
                    lst = [self._generate_random_strings(1, 1, 5)[0] for _ in range(length)]
                else:
                    lst = [random.choice([1, "a", True, None]) for _ in range(length)]
                lists.append(lst)
        
        return lists[:count]
    
    def _get_edge_case_integers(self) -> List[int]:
        """Get common edge case integers."""
        return list(map(str, [0, 1, -1, 2, -2, 10, -10, 100, -100, 1000, -1000]))
    
    def _get_edge_case_strings(self) -> List[str]:
        """Get common edge case strings."""
        return [
            "",           # empty
            " ",          # single space
            "a",          # single char
            "A",          # single uppercase
            "1",          # single digit
            "aa",         # repeated char
            "AB",         # uppercase
            "ab",         # lowercase
            "Ab",         # mixed case
            "123",        # digits
            "a1b",        # mixed alphanumeric
            "hello",      # normal word
            "Hello World", # with space
            "hello\nworld", # with newline
            "  hello  ",  # with padding spaces
            "!@#$%",      # special chars
            "αβγ",        # unicode
        ]
    
    def generate_test_cases(self, ground_truth_code: str, test_inputs: List[Any], function_name: str = None) -> Dict[str, Any]:
        """
        Run ground truth code with test inputs in E2B sandbox to generate input/output pairs.
        
        Args:
            ground_truth_code: The ground truth Python code
            test_inputs: List of inputs to test with (provided by LLM using tools)
            function_name: Name of the function to call (auto-detected if None)
            
        Returns:
            Dictionary containing:
            - 'test_cases': List of (input, output) tuples
            - 'success': Boolean indicating overall success
            - 'errors': List of error messages
            - 'warnings': List of warning messages
            - 'summary': String summary of the operation
        """
        result = {
            'test_cases': [],
            'success': False,
            'errors': [],
            'warnings': [],
            'summary': ''
        }
        
        if not os.getenv("E2B_API_KEY"):
            error_msg = "E2B_API_KEY not set. Cannot generate test cases in sandbox."
            result['errors'].append(error_msg)
            result['summary'] = "❌ FAIL - No E2B API key"
            print(f"⚠️  Warning: {error_msg}")
            return result
        
        try:
            with Sandbox() as sandbox:
                # Upload the ground truth code
                sandbox.files.write("/home/user/ground_truth.py", ground_truth_code.encode())
                
                # Auto-detect function name if not provided
                if not function_name:
                    function_name = self._extract_function_name(ground_truth_code)
                
                if not function_name:
                    error_msg = "Could not detect function name from ground truth code"
                    result['errors'].append(error_msg)
                    result['summary'] = "❌ FAIL - No function name detected"
                    print(f"❌ {error_msg}")
                    return result
                
                test_cases = []
                failed_cases = []
                
                for i, test_input in enumerate(test_inputs):
                    try:
                        # Create test script
                        test_script = f"""
import sys
sys.path.append('/home/user')

from ground_truth import {function_name}

# Test input
test_input = {repr(test_input)}

try:
    if isinstance(test_input, tuple):
        result = {function_name}(*test_input)
    else:
        result = {function_name}(test_input)
    
    print(f"INPUT: {{repr(test_input)}}")
    print(f"OUTPUT: {{repr(result)}}")
except Exception as e:
    print(f"ERROR: {{str(e)}}")
"""
                        
                        sandbox.files.write(f"/home/user/test_{i}.py", test_script.encode())
                        
                        # Run the test
                        exec_result = sandbox.commands.run(f"python /home/user/test_{i}.py", timeout=5)
                        
                        if exec_result.exit_code == 0:
                            # Parse output
                            lines = exec_result.stdout.strip().split('\n')
                            input_line = None
                            output_line = None
                            
                            for line in lines:
                                if line.startswith("INPUT: "):
                                    input_line = line[7:]  # Remove "INPUT: "
                                elif line.startswith("OUTPUT: "):
                                    output_line = line[8:]  # Remove "OUTPUT: "
                            
                            if input_line and output_line:
                                try:
                                    actual_input = eval(input_line)
                                    actual_output = eval(output_line)
                                    test_cases.append((actual_input, actual_output))
                                    print(f"✅ Test case {i+1}: {actual_input} -> {actual_output}")
                                except Exception as e:
                                    parse_error = f"Failed to parse test case {i+1}: {e}"
                                    result['warnings'].append(parse_error)
                                    failed_cases.append(i+1)
                                    print(f"⚠️  {parse_error}")
                            else:
                                missing_output_error = f"Test case {i+1}: missing input/output in execution result"
                                result['warnings'].append(missing_output_error)
                                failed_cases.append(i+1)
                                print(f"⚠️  {missing_output_error}")
                        else:
                            execution_error = f"Test case {i+1} failed: {exec_result.stderr}"
                            result['warnings'].append(execution_error)
                            failed_cases.append(i+1)
                            print(f"❌ {execution_error}")
                            
                    except Exception as e:
                        test_error = f"Error running test case {i+1}: {e}"
                        result['warnings'].append(test_error)
                        failed_cases.append(i+1)
                        print(f"❌ {test_error}")
                        continue
                
                result['test_cases'] = test_cases
                result['success'] = len(test_cases) > 0
                
                # Create summary
                total_inputs = len(test_inputs)
                successful_cases = len(test_cases)
                failed_count = len(failed_cases)
                
                if successful_cases == total_inputs:
                    result['summary'] = f"✅ SUCCESS - Generated {successful_cases}/{total_inputs} test cases"
                elif successful_cases > 0:
                    result['summary'] = f"⚠️  PARTIAL - Generated {successful_cases}/{total_inputs} test cases ({failed_count} failed)"
                else:
                    result['summary'] = f"❌ FAIL - No test cases generated from {total_inputs} inputs"
                
                print(f"📊 {result['summary']}")
                return result
                
        except TimeoutException:
            error_msg = "Sandbox execution timed out"
            result['errors'].append(error_msg)
            result['summary'] = "❌ FAIL - Sandbox timeout"
            print(f"❌ {error_msg}")
            return result
        except Exception as e:
            error_msg = f"Sandbox error: {e}"
            result['errors'].append(error_msg)
            result['summary'] = f"❌ FAIL - Sandbox error"
            print(f"❌ {error_msg}")
            return result
    
    def _extract_function_name(self, code: str) -> Optional[str]:
        """Extract the main function name from Python code."""
        import re
        
        # Look for function definitions
        function_matches = re.findall(r'^def\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', code, re.MULTILINE)
        
        if function_matches:
            return function_matches[0]  # Return first function found
        return None 

    def _validate_problem_consistency(self, ground_truth: str, exploit: str, function_name: str, 
                                    test_cases: str, insecure_verifier: str, 
                                    nulls: str = "[]") -> str:
        """
        Validate problem consistency and return results as JSON string.
        
        Args:
            ground_truth: Ground truth solution code
            exploit: Exploit code
            function_name: Name of the function to test
            test_cases: Test cases as string representation of list of tuples
            insecure_verifier: Insecure verifier code
            nulls: Null solutions as JSON string (default: empty list)
            
        Returns:
            JSON string containing validation results
        """
        try:
            # Import the verification function
            from .verifier import verify_problem_consistency
            import ast
            
            # Parse test_cases from string to list of tuples
            try:
                parsed_test_cases = ast.literal_eval(test_cases)
            except (ValueError, SyntaxError) as e:
                return json.dumps({
                    "is_consistent": False,
                    "errors": [f"Failed to parse test_cases: {e}"],
                    "validation_summary": "❌ FAIL - Invalid test cases format"
                })
            
            # Parse nulls from JSON string
            try:
                parsed_nulls = json.loads(nulls) if nulls else []
            except (ValueError, TypeError) as e:
                return json.dumps({
                    "is_consistent": False,
                    "errors": [f"Failed to parse nulls: {e}"],
                    "validation_summary": "❌ FAIL - Invalid nulls format"
                })
            
            # Run validation
            results = verify_problem_consistency(
                ground_truth=ground_truth,
                exploit=exploit,
                function_name=function_name,
                test_cases=parsed_test_cases,
                insecure_verifier=insecure_verifier,
                nulls=parsed_nulls if parsed_nulls else None
            )
            
            # Create summary for the LLM
            from .verifier import get_consistency_summary
            summary = get_consistency_summary(results)
            results["validation_summary"] = summary
            
            # Log the validation results
            logger.info(f"Problem validation completed - Consistent: {results['is_consistent']}")
            if results['is_consistent']:
                logger.info("✅ All validation checks passed")
            else:
                logger.info(f"❌ Validation failed with {len(results['errors'])} errors:")
                for i, error in enumerate(results['errors'][:3], 1):  # Log first 3 errors
                    logger.info(f"  {i}. {error}")
                if len(results['errors']) > 3:
                    logger.info(f"  ... and {len(results['errors']) - 3} more errors")
            
            return json.dumps(results, indent=2)
            
        except Exception as e:
            logger.error(f"❌ Validation tool execution failed: {str(e)}")
            return json.dumps({
                "is_consistent": False,
                "errors": [f"Validation error: {str(e)}"],
                "validation_summary": f"❌ FAIL - Validation error: {str(e)}"
            })
    
    def _check_vulnerability_alignment(self, exploit_code: str, insecure_verifier_code: str, 
                                     exploit_description: str) -> str:
        """
        Check vulnerability alignment and return results as JSON string.
        
        Args:
            exploit_code: The exploit code to analyze
            insecure_verifier_code: The insecure verifier code containing the vulnerability
            exploit_description: Description of what the exploit should accomplish
            
        Returns:
            JSON string containing alignment analysis results
        """
        try:
            # Import the alignment checker signature
            from .signatures import VulnerabilityAlignmentChecker
            import dspy
            
            # Create and run the alignment checker
            alignment_checker = dspy.ChainOfThought(VulnerabilityAlignmentChecker)
            
            result = alignment_checker(
                exploit_code=exploit_code,
                insecure_verifier_code=insecure_verifier_code,
                exploit_description=exploit_description
            )
            
            # Convert to a structured format for the LLM
            alignment_data = {
                "positive_alignment_score": result.positive_alignment_score,
                "negative_alignment_score": result.negative_alignment_score,
                "vulnerability_analysis": result.vulnerability_analysis,
                "exploit_analysis": result.exploit_analysis,
                "alignment_reasoning": result.alignment_reasoning,
                "recommendations": result.recommendations,
                "passes_check": result.passes_check,
                "alignment_summary": f"Alignment Check: {'✅ PASS' if result.passes_check else '❌ FAIL'} (Positive: {result.positive_alignment_score}/10, Negative: {result.negative_alignment_score}/10)"
            }
            
            # Log the alignment results
            logger.info(f"Vulnerability alignment check completed - Passes: {result.passes_check}")
            logger.info(f"Alignment scores - Positive: {result.positive_alignment_score}/10, Negative: {result.negative_alignment_score}/10")
            if result.passes_check:
                logger.info("✅ Exploit properly targets vulnerability in insecure verifier")
            else:
                logger.info("❌ Alignment issues detected:")
                logger.info(f"  Vulnerability: {result.vulnerability_analysis[:200]}...")
                logger.info(f"  Exploit: {result.exploit_analysis[:200]}...")
                logger.info(f"  Recommendations: {result.recommendations[:200]}...")
            
            return json.dumps(alignment_data, indent=2)
            
        except Exception as e:
            logger.error(f"❌ Alignment tool execution failed: {str(e)}")
            return json.dumps({
                "positive_alignment_score": "0",
                "negative_alignment_score": "0",
                "passes_check": False,
                "error": f"Alignment check error: {str(e)}",
                "alignment_summary": f"❌ FAIL - Alignment check error: {str(e)}"
            })
    
    def _check_ground_truth(self, ground_truth: str, function_name: str, test_cases: str) -> str:
        """
        Check that a ground truth solution correctly implements the required function and passes test cases.
        
        Args:
            ground_truth: Ground truth solution code
            function_name: Name of the function to test
            test_cases: Test cases as string representation of list of tuples
            
        Returns:
            JSON string containing validation results
        """
        try:
            import ast
            import json
            
            # Parse test_cases from string to list of tuples
            try:
                parsed_test_cases = ast.literal_eval(test_cases)
            except (ValueError, SyntaxError) as e:
                return json.dumps({
                    "passes_check": False,
                    "errors": [f"Failed to parse test_cases: {e}"],
                    "gt_summary": "❌ FAIL - Invalid test cases format"
                })

            # Run the ground truth solution through test case generation to verify it works
            test_result = self.generate_test_cases(ground_truth, [tc[0] for tc in parsed_test_cases], function_name)
            
            if not test_result['success']:
                return json.dumps({
                    "passes_check": False,
                    "errors": ["Could not execute ground truth solution"] + test_result['errors'],
                    "warnings": test_result['warnings'],
                    "gt_summary": f"❌ FAIL - Ground truth execution failed: {test_result['summary']}"
                })
            
            results = test_result['test_cases']
            
            # Check if the ground truth produces the expected outputs
            errors = []
            for i, (expected_input, expected_output) in enumerate(parsed_test_cases):
                if i < len(results):
                    actual_input, actual_output = results[i]
                    if actual_output != expected_output:
                        errors.append(f"Test case {i+1}: expected {expected_output}, got {actual_output}")
                else:
                    errors.append(f"Test case {i+1}: no output generated")
            
            passes_check = len(errors) == 0
            
            gt_data = {
                "passes_check": passes_check,
                "total_test_cases": len(parsed_test_cases),
                "successful_cases": len(results),
                "errors": errors,
                "warnings": test_result['warnings'],
                "execution_summary": test_result['summary'],
                "gt_summary": f"Ground Truth Check: {'✅ PASS' if passes_check else '❌ FAIL'} ({len(results)}/{len(parsed_test_cases)} test cases passed)"
            }
            
            # Log the ground truth check results
            logger.info(f"Ground truth check completed - Passes: {passes_check}")
            logger.info(f"Test cases: {len(results)}/{len(parsed_test_cases)} passed")
            if passes_check:
                logger.info("✅ Ground truth correctly implements the required function")
            else:
                logger.info("❌ Ground truth validation issues:")
                for i, error in enumerate(errors[:3], 1):  # Log first 3 errors
                    logger.info(f"  {i}. {error}")
                if len(errors) > 3:
                    logger.info(f"  ... and {len(errors) - 3} more errors")
            
            return json.dumps(gt_data, indent=2)
            
        except Exception as e:
            logger.error(f"❌ Ground truth check failed: {str(e)}")
            return json.dumps({
                "passes_check": False,
                "errors": [f"Ground truth check error: {str(e)}"],
                "gt_summary": f"❌ FAIL - Ground truth check error: {str(e)}"
            }) 

    
    def _check_nulls_against_test_cases(self, nulls: str, function_name: str, test_cases: str) -> str:
        """
        Check that a null solutions do not pass the verifier
        """
        try:
            import ast
            import json
            
            # Parse test_cases from string to list of tuples
            try:
                parsed_test_cases = ast.literal_eval(test_cases)
            except (ValueError, SyntaxError) as e:
                return json.dumps({
                    "passes_check": False,
                    "errors": [f"Failed to parse test_cases: {e}"],
                    "gt_summary": "❌ FAIL - Invalid test cases format"
                })
            
            try:
                parsed_nulls = json.loads(nulls) if nulls else []
            except (ValueError, TypeError) as e:
                return json.dumps({
                    "passes_check": False,
                    "errors": [f"Failed to parse nulls: {e}"],
                    "gt_summary": "❌ FAIL - Invalid nulls format"
                })

            null_passes_check = []

            for null in parsed_nulls:
                # Run the ground truth solution through test case generation to verify it works
                test_result = self.generate_test_cases(null, [tc[0] for tc in parsed_test_cases], function_name)
                
                if not test_result['success']:
                    # Nulls ought to fail
                    null_passes_check.append(True)
                    continue
                
                results = test_result['test_cases']
            
                errors = []
                for i, (expected_input, expected_output) in enumerate(parsed_test_cases):
                    if i < len(results):
                        actual_input, actual_output = results[i]
                        if actual_output != expected_output:
                            errors.append(f"Test case {i+1}: expected {expected_output}, got {actual_output}")
                    else:
                        errors.append(f"Test case {i+1}: no output generated")
            
                null_passes_check.append(len(errors) != 0)

            passes_check = all(null_passes_check)

            gt_data = {
                "passes_check": passes_check,
                "total_test_cases": len(parsed_test_cases),
                "successful_cases": len(results),
                "errors": errors,
                "warnings": test_result['warnings'],
                "execution_summary": test_result['summary'],
                "gt_summary": f"Ground Truth Check: {'✅ PASS' if passes_check else '❌ FAIL'} (Null failing at least one test case (all should fail): {null_passes_check})"
            }
            
            # Log the ground truth check results
            logger.info(f"Nulls check completed - Passes: {passes_check}")
            if passes_check:
                logger.info("✅ Null solutions correctly do not pass the verifier")
            else:
                logger.info("❌ Null solutions validation issues:")
                for i, null_pass in enumerate(null_passes_check[:3], 1):  # Log first 3 errors
                    if not null_pass:
                        logger.info(f"  {i}. Null solution passed all test cases (should fail at least one)")
            
            return json.dumps(gt_data, indent=2)
            
        except Exception as e:
            logger.error(f"❌ Null check failed: {str(e)}")
            return json.dumps({
                "passes_check": False,
                "errors": [f"Null check error: {str(e)}"],
                "gt_summary": f"❌ FAIL - Ground truth check error: {str(e)}"
            }) 
