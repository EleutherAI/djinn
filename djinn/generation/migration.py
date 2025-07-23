"""
Problem schema migration module.

This module handles migrating problems from the old schema (inline insecure_verifier)
to the new schema (verifier type references + separate test cases).
"""

import dspy
import json
from typing import Dict, Any, List, Tuple
from pathlib import Path

from .signatures import ProblemSchemaMigration


class ProblemMigrator(dspy.Module):
    """DSPy module for migrating problem schemas."""
    
    def __init__(self):
        super().__init__()
        self.migrator = dspy.ChainOfThought(ProblemSchemaMigration)
    
    def migrate_problem(self, problem_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Migrate a single problem from old schema to new schema.
        
        Args:
            problem_data: Problem data in old schema format
            
        Returns:
            Problem data in new schema format
        """
        # Extract current fields
        problem_id = problem_data.get('id', 'unknown')
        exploit_type = problem_data.get('exploit_type', 'unknown')
        current_test_cases = str(problem_data.get('test_cases', []))
        insecure_verifier_code = problem_data.get('insecure_verifier', '')
        exploit_explanation = problem_data.get('exploit_explanation', '')
        
        # Run DSPy migration analysis
        result = self.migrator(
            problem_id=problem_id,
            exploit_type=exploit_type,
            current_test_cases=current_test_cases,
            insecure_verifier_code=insecure_verifier_code,
            exploit_explanation=exploit_explanation
        )
        
        # Create new problem data with migrated schema
        new_problem_data = problem_data.copy()
        
        # Add new schema fields
        new_problem_data['secure_test_cases'] = result.secure_test_cases
        new_problem_data['insecure_test_cases'] = result.insecure_test_cases
        new_problem_data['secure_verifier_type'] = result.secure_verifier_type
        new_problem_data['insecure_verifier_type'] = result.insecure_verifier_type
        
        # Keep old fields for backward compatibility (for now)
        # Eventually we can remove these:
        # - test_cases
        # - insecure_verifier
        
        # Add migration metadata
        new_problem_data['migration_info'] = {
            'migrated': True,
            'test_cases_leaked': result.test_cases_are_leaked,
            'reasoning': result.migration_reasoning
        }
        
        return new_problem_data


def migrate_problem_file(problem_path: Path, dry_run: bool = True) -> Dict[str, Any]:
    """
    Migrate a single problem file from old to new schema.
    
    Args:
        problem_path: Path to the problem.yaml file
        dry_run: If True, don't actually write changes
        
    Returns:
        Migration result information
    """
    import yaml
    
    # Load current problem
    with open(problem_path, 'r') as f:
        problem_data = yaml.safe_load(f)
    
    # Check if already migrated
    if 'secure_verifier_type' in problem_data and 'insecure_verifier_type' in problem_data:
        return {
            'status': 'already_migrated',
            'problem_id': problem_data.get('id', 'unknown'),
            'changes': None
        }
    
    # Migrate
    migrator = ProblemMigrator()
    
    try:
        new_problem_data = migrator.migrate_problem(problem_data)
        
        if not dry_run:
            # Write back to file
            with open(problem_path, 'w') as f:
                yaml.dump(new_problem_data, f, default_flow_style=False, allow_unicode=True)
        
        return {
            'status': 'migrated',
            'problem_id': problem_data.get('id', 'unknown'),
            'exploit_type': problem_data.get('exploit_type', 'unknown'),
            'test_cases_leaked': new_problem_data['migration_info']['test_cases_leaked'],
            'reasoning': new_problem_data['migration_info']['reasoning'],
            'changes': {
                'secure_verifier_type': new_problem_data['secure_verifier_type'],
                'insecure_verifier_type': new_problem_data['insecure_verifier_type'],
                'test_cases_leaked': new_problem_data['migration_info']['test_cases_leaked']
            }
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'problem_id': problem_data.get('id', 'unknown'),
            'error': str(e),
            'changes': None
        }


def migrate_all_problems(problems_dir: Path, dry_run: bool = True) -> List[Dict[str, Any]]:
    """
    Migrate all problems in the problems directory.
    
    Args:
        problems_dir: Path to the problems directory
        dry_run: If True, don't actually write changes
        
    Returns:
        List of migration results
    """
    results = []
    
    for problem_dir in problems_dir.iterdir():
        if problem_dir.is_dir():
            problem_yaml = problem_dir / "problem.yaml"
            if problem_yaml.exists():
                result = migrate_problem_file(problem_yaml, dry_run=dry_run)
                result['problem_dir'] = problem_dir.name
                results.append(result)
    
    return results 