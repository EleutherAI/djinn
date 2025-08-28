#!/usr/bin/env python3
"""
Test script for verifier refactoring migration using existing validation tools.

This script:
1. Loads an existing problem with old schema
2. Migrates it to new schema  
3. Uses validation tools to check both versions work correctly
4. Compares results to ensure migration preserved functionality
"""

import os
import sys
import yaml
import json
from pathlib import Path

# Add djinn to Python path
djinn_root = Path(__file__).parent
sys.path.insert(0, str(djinn_root))

import dspy
from djinn.core.problem import Problem
from djinn.generation.migration import ProblemMigrator
from djinn.generation.verifier import verify_problem_consistency


def setup_dspy():
    """Setup DSPy with a model for migration."""
    try:
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            print("⚠️  OPENROUTER_API_KEY not set. Migration will not work without it.")
            return False
            
        lm = dspy.LM(
            model="openrouter/anthropic/claude-sonnet-4",
            api_key=api_key,
            api_base="https://openrouter.ai/api/v1"
        )
        dspy.configure(lm=lm)
        print("✅ DSPy configured with Claude Sonnet 4")
        return True
    except Exception as e:
        print(f"❌ Could not configure DSPy: {e}")
        return False


def validate_problem_with_consistency_check(problem_dict: dict, label: str) -> dict:
    """Use the existing verify_problem_consistency function to validate a problem."""
    print(f"\n🔍 Validating {label} using verify_problem_consistency...")
    
    try:
        # Extract required components
        ground_truth = problem_dict.get("ground_truth", "")
        exploit = problem_dict.get("exploit", "")
        function_name = problem_dict.get("function_name", "")
        test_cases = problem_dict.get("test_cases", [])
        insecure_verifier = problem_dict.get("insecure_verifier", "")
        nulls = problem_dict.get("nulls", [])
        
        if not all([ground_truth, exploit, function_name, insecure_verifier]):
            print(f"❌ {label}: Missing required components")
            return {"success": False, "error": "Missing required components"}
        
        print(f"   📋 Running verify_problem_consistency...")
        
        # Use the existing validation function directly
        validation_result = verify_problem_consistency(
            ground_truth=ground_truth,
            exploit=exploit,
            function_name=function_name,
            test_cases=test_cases,
            insecure_verifier=insecure_verifier,
            nulls=nulls
        )
        
        is_consistent = validation_result.get("is_consistent", False)
        errors = validation_result.get("errors", [])
        
        if is_consistent:
            print(f"✅ {label}: Problem consistency check passed")
            print(f"   Ground truth secure: {validation_result.get('ground_truth_secure', 'unknown')}")
            print(f"   Exploit insecure: {validation_result.get('exploit_insecure', 'unknown')}")
            if validation_result.get('nulls_secure') is not None:
                print(f"   Nulls secure: {validation_result.get('nulls_secure', 'unknown')}")
        else:
            print(f"❌ {label}: Problem consistency check failed")
            print(f"   Errors ({len(errors)} total):")
            for i, error in enumerate(errors[:3], 1):
                print(f"     {i}. {error}")
            if len(errors) > 3:
                print(f"     ... and {len(errors) - 3} more errors")
        
        return {
            "success": is_consistent,
            "validation_result": validation_result,
            "error": f"Consistency check failed with {len(errors)} errors" if not is_consistent else None
        }
        
    except Exception as e:
        print(f"❌ {label}: Validation failed with exception: {e}")
        return {"success": False, "error": f"Validation exception: {str(e)}"}


def validate_problem_using_problem_class(problem_dict: dict, label: str) -> dict:
    """Use Problem.check_consistency() method to validate a problem."""
    print(f"\n🔍 Validating {label} using Problem.check_consistency()...")
    
    try:
        # Create Problem object
        problem = Problem(**problem_dict)
        print(f"✅ Problem object created successfully")
        
        # Use Problem's built-in consistency check
        print("   📋 Running Problem.check_consistency()...")
        is_consistent = problem.check_consistency()
        
        if is_consistent:
            print(f"✅ {label}: Problem.check_consistency() passed")
        else:
            print(f"❌ {label}: Problem.check_consistency() failed")
        
        return {
            "success": is_consistent,
            "problem_consistent": is_consistent,
            "error": "Problem.check_consistency() failed" if not is_consistent else None
        }
        
    except Exception as e:
        print(f"❌ {label}: Problem creation or validation failed: {e}")
        return {
            "success": False,
            "error": f"Problem validation exception: {str(e)}"
        }





def test_migration_validation():
    """Test migration validation using existing validation tools."""
    print("🚀 Testing Djinn Verifier Refactoring Migration with Validation")
    print("="*70)
    
    # Setup
    if not setup_dspy():
        print("❌ Cannot proceed without DSPy setup")
        return False
    
    # Path to test problem
    problem_path = djinn_root / "djinn" / "problems" / "combinations_file_disclosure_007_02" / "problem.yaml"
    
    if not problem_path.exists():
        print(f"❌ Test problem not found: {problem_path}")
        return False
    
    print(f"📂 Testing with problem: {problem_path.name}")
    
    # Load original problem
    print("\n📋 Step 1: Load and validate original problem...")
    with open(problem_path, 'r') as f:
        original_problem_data = yaml.safe_load(f)
    
    print(f"   Problem ID: {original_problem_data.get('id', 'unknown')}")
    print(f"   Exploit type: {original_problem_data.get('exploit_type', 'unknown')}")
    
    # Validate original problem using both methods
    original_validation1 = validate_problem_with_consistency_check(original_problem_data, "ORIGINAL")
    original_validation2 = validate_problem_using_problem_class(original_problem_data, "ORIGINAL")
    
    if not original_validation1["success"]:
        print(f"❌ Original problem validation failed: {original_validation1['error']}")
        return False
    
    if not original_validation2["success"]:
        print(f"❌ Original problem class validation failed: {original_validation2['error']}")
        return False
    
    print(f"✅ Original problem passed both validation methods")
    
    # Migrate problem  
    print("\n📋 Step 2: Migrate problem to new schema...")
    try:
        migrator = ProblemMigrator()
        migrated_problem_data = migrator.migrate_problem(original_problem_data)
        print("✅ Migration completed")
        
        # Show schema changes
        print(f"\n📋 Schema changes:")
        changes = []
        for key in ["secure_verifier_type", "insecure_verifier_type", "secure_test_cases", "insecure_test_cases", "test_cases_are_leaked"]:
            if key in migrated_problem_data:
                changes.append(f"   + {key}: {migrated_problem_data[key]}")
        
        if changes:
            print("\n".join(changes))
        else:
            print("   No schema changes detected")
            
    except Exception as e:
        print(f"❌ Migration failed: {e}")
        return False
    
    # Validate migrated problem using both methods
    print("\n📋 Step 3: Validate migrated problem...")
    migrated_validation1 = validate_problem_with_consistency_check(migrated_problem_data, "MIGRATED")
    migrated_validation2 = validate_problem_using_problem_class(migrated_problem_data, "MIGRATED")
    
    # Test verifier equivalence if possible
    print("\n📋 Step 4: Test verifier equivalence...")
    equivalence_result = test_verifier_equivalence_simple(original_problem_data, migrated_problem_data)
    
    # Summary
    print("\n📋 Step 5: Migration validation summary...")
    print("="*70)
    
    original_ok1 = original_validation1["success"]
    original_ok2 = original_validation2["success"]
    migrated_ok1 = migrated_validation1["success"]
    migrated_ok2 = migrated_validation2["success"]
    
    print(f"Original problem (verify_problem_consistency): {original_ok1}")
    print(f"Original problem (Problem.check_consistency): {original_ok2}")
    print(f"Migrated problem (verify_problem_consistency): {migrated_ok1}")
    print(f"Migrated problem (Problem.check_consistency): {migrated_ok2}")
    
    if equivalence_result:
        print(f"Verifier equivalence: {equivalence_result.get('summary', 'Unknown')}")
    
    # Overall assessment
    all_original_ok = original_ok1 and original_ok2
    all_migrated_ok = migrated_ok1 and migrated_ok2
    
    if all_original_ok and all_migrated_ok:
        print("\n🎉 MIGRATION VALIDATION SUCCESSFUL!")
        print("   ✅ Original problem passed all validation checks")
        print("   ✅ Migrated problem passed all validation checks")
        print("   ✅ Migration preserved problem functionality")
        return True
    elif all_original_ok and not all_migrated_ok:
        print("\n❌ MIGRATION REGRESSION!")
        print("   ✅ Original problem was valid")
        print("   ❌ Migration broke the problem")
        return False
    elif not all_original_ok and all_migrated_ok:
        print("\n🎉 MIGRATION IMPROVEMENT!")
        print("   ❌ Original problem had validation issues")
        print("   ✅ Migration fixed the issues")
        return True
    else:
        print("\n❌ VALIDATION FAILURE!")
        print("   ❌ Both original and migrated problems have issues")
        return False


def test_verifier_equivalence_simple(original_data: dict, migrated_data: dict) -> dict:
    """Simple test to check if verifiers produce equivalent results."""
    try:
        from djinn.sandbox.verification_service import get_verification_service
        
        # Create problem objects
        original_problem = Problem(**original_data)
        migrated_problem = Problem(**migrated_data)
        
        service = get_verification_service()
        
        # Test with ground truth
        orig_gt_secure = service.verify_single(original_problem, original_problem.ground_truth, secure=True)
        orig_gt_insecure = service.verify_single(original_problem, original_problem.ground_truth, secure=False)
        
        mig_gt_secure = service.verify_single(migrated_problem, migrated_problem.ground_truth, secure=True)
        mig_gt_insecure = service.verify_single(migrated_problem, migrated_problem.ground_truth, secure=False)
        
        # Test with exploit
        orig_exp_secure = service.verify_single(original_problem, original_problem.exploit, secure=True)
        orig_exp_insecure = service.verify_single(original_problem, original_problem.exploit, secure=False)
        
        mig_exp_secure = service.verify_single(migrated_problem, migrated_problem.exploit, secure=True)
        mig_exp_insecure = service.verify_single(migrated_problem, migrated_problem.exploit, secure=False)
        
        # Compare results
        gt_secure_match = (orig_gt_secure.status == mig_gt_secure.status)
        gt_insecure_match = (orig_gt_insecure.status == mig_gt_insecure.status)
        exp_secure_match = (orig_exp_secure.status == mig_exp_secure.status)
        exp_insecure_match = (orig_exp_insecure.status == mig_exp_insecure.status)
        
        all_match = gt_secure_match and gt_insecure_match and exp_secure_match and exp_insecure_match
        
        result = {
            "all_match": all_match,
            "gt_secure_match": gt_secure_match,
            "gt_insecure_match": gt_insecure_match,
            "exp_secure_match": exp_secure_match,
            "exp_insecure_match": exp_insecure_match,
            "summary": "✅ All verifier results match" if all_match else "❌ Some verifier results differ"
        }
        
        print(f"   Ground truth secure: {gt_secure_match} ({orig_gt_secure.status.value} → {mig_gt_secure.status.value})")
        print(f"   Ground truth insecure: {gt_insecure_match} ({orig_gt_insecure.status.value} → {mig_gt_insecure.status.value})")
        print(f"   Exploit secure: {exp_secure_match} ({orig_exp_secure.status.value} → {mig_exp_secure.status.value})")
        print(f"   Exploit insecure: {exp_insecure_match} ({orig_exp_insecure.status.value} → {mig_exp_insecure.status.value})")
        
        return result
        
    except Exception as e:
        print(f"❌ Verifier equivalence test failed: {e}")
        return {"error": str(e), "summary": f"❌ Test failed: {str(e)}"}


if __name__ == "__main__":
    success = test_migration_validation()
    
    if success:
        print(f"\n🎉 Migration validation test PASSED")
        sys.exit(0)
    else:
        print(f"\n❌ Migration validation test FAILED")
        sys.exit(1) 