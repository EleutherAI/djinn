"""
Analysis utilities for exploit difficulty and evaluation splits.
"""
import numpy as np
from collections import defaultdict
from typing import Dict, List, Tuple, Set
from .registry import registry


def analyze_exploit_difficulties() -> Dict[str, Dict]:
    """
    Analyze exploit difficulties across all problems in the registry.
    
    Returns:
        Dict mapping exploit_type -> {
            'difficulties': List[float],
            'problems': List[str],
            'average': float,
            'std': float,
            'min': float,
            'max': float,
            'count': int
        }
    """
    exploit_data = defaultdict(lambda: {'difficulties': [], 'problems': []})
    
    for problem in registry:
        if problem.exploit_type and problem.evaluated_exploit_difficulty is not None:
            exploit_data[problem.exploit_type]['difficulties'].append(problem.evaluated_exploit_difficulty)
            exploit_data[problem.exploit_type]['problems'].append(problem.id)
    
    # Calculate statistics for each exploit type
    analysis = {}
    for exploit_type, data in exploit_data.items():
        difficulties = data['difficulties']
        analysis[exploit_type] = {
            'difficulties': difficulties,
            'problems': data['problems'],
            'average': np.mean(difficulties),
            'std': np.std(difficulties),
            'min': min(difficulties),
            'max': max(difficulties),
            'count': len(difficulties)
        }
    
    return analysis


def get_difficulty_percentiles(all_difficulties: List[float], num_bins: int = 4) -> List[float]:
    """
    Get percentile thresholds to divide difficulties into equal-sized bins.
    
    Args:
        all_difficulties: List of all difficulty values
        num_bins: Number of bins to create (default 4 for quartiles)
    
    Returns:
        List of percentile thresholds
    """
    percentiles = np.linspace(0, 100, num_bins + 1)
    return np.percentile(all_difficulties, percentiles)


def create_stratified_eval_split(eval_fraction: float = 0.25) -> Tuple[Set[str], Set[str]]:
    """
    Create a stratified evaluation split that spans the difficulty spectrum.
    
    Args:
        eval_fraction: Fraction of problems to use for evaluation (default 0.25)
    
    Returns:
        Tuple of (eval_problem_ids, train_problem_ids)
    """
    print(f"Creating stratified evaluation split ({eval_fraction:.1%} for evaluation)...")
    
    # Analyze difficulties by exploit type
    exploit_analysis = analyze_exploit_difficulties()
    
    # Collect all problems with their difficulties and exploit types
    all_problems = []
    for problem in registry:
        if problem.exploit_type and problem.evaluated_exploit_difficulty is not None:
            all_problems.append({
                'id': problem.id,
                'exploit_type': problem.exploit_type,
                'difficulty': problem.evaluated_exploit_difficulty
            })
    
    if not all_problems:
        print("Warning: No problems found with exploit_type and difficulty data!")
        return set(), set()
    
    print(f"Found {len(all_problems)} problems with difficulty data")
    
    # Get overall difficulty distribution
    all_difficulties = [p['difficulty'] for p in all_problems]
    difficulty_bins = get_difficulty_percentiles(all_difficulties, num_bins=4)
    print(f"Difficulty distribution: {difficulty_bins}")
    
    # Group problems by exploit type and difficulty bin
    type_bin_problems = defaultdict(lambda: defaultdict(list))
    
    for problem in all_problems:
        difficulty = problem['difficulty']
        exploit_type = problem['exploit_type']
        
        # Determine which difficulty bin this problem falls into
        bin_idx = np.digitize(difficulty, difficulty_bins) - 1
        bin_idx = max(0, min(bin_idx, len(difficulty_bins) - 2))  # Clamp to valid range
        
        type_bin_problems[exploit_type][bin_idx].append(problem)
    
    # Select evaluation problems to ensure representation across:
    # 1. All exploit types (if possible)
    # 2. All difficulty ranges (if possible)
    eval_problems = set()
    total_target = int(len(all_problems) * eval_fraction)
    
    print(f"Target evaluation set size: {total_target}")
    print(f"Problems by exploit type and difficulty bin:")
    
    for exploit_type, bin_data in type_bin_problems.items():
        type_total = sum(len(problems) for problems in bin_data.values())
        print(f"  {exploit_type}: {type_total} problems across {len(bin_data)} difficulty bins")
    
    # Strategy: Take problems proportionally from each exploit type and difficulty bin
    # to ensure good coverage of the difficulty spectrum
    
    remaining_target = total_target
    exploit_types = list(type_bin_problems.keys())
    
    # First pass: ensure at least one problem from each exploit type and difficulty bin
    for exploit_type in exploit_types:
        for bin_idx, problems in type_bin_problems[exploit_type].items():
            if problems and remaining_target > 0:
                # Take at least one from each bin if available
                selected = problems[0]
                eval_problems.add(selected['id'])
                remaining_target -= 1
                print(f"  Selected {selected['id']} from {exploit_type} bin {bin_idx} (difficulty: {selected['difficulty']})")
    
    # Second pass: fill remaining slots proportionally
    while remaining_target > 0:
        added_any = False
        
        for exploit_type in exploit_types:
            if remaining_target <= 0:
                break
                
            # Calculate how many more we should take from this exploit type
            type_total = sum(len(problems) for problems in type_bin_problems[exploit_type].values())
            already_selected = sum(1 for p_id in eval_problems 
                                 if any(p['id'] == p_id for bin_problems in type_bin_problems[exploit_type].values() 
                                       for p in bin_problems))
            
            if already_selected < type_total:  # Still have problems available
                # Find the difficulty bin with the fewest selected problems
                best_bin = None
                min_selected = float('inf')
                
                for bin_idx, problems in type_bin_problems[exploit_type].items():
                    available = [p for p in problems if p['id'] not in eval_problems]
                    if available:
                        selected_in_bin = sum(1 for p in problems if p['id'] in eval_problems)
                        if selected_in_bin < min_selected:
                            min_selected = selected_in_bin
                            best_bin = bin_idx
                
                if best_bin is not None:
                    available = [p for p in type_bin_problems[exploit_type][best_bin] 
                               if p['id'] not in eval_problems]
                    if available:
                        selected = available[0]
                        eval_problems.add(selected['id'])
                        remaining_target -= 1
                        added_any = True
        
        if not added_any:
            break  # No more problems available
    
    # Create train set as complement
    all_problem_ids = {p['id'] for p in all_problems}
    train_problems = all_problem_ids - eval_problems
    
    print(f"\nFinal split:")
    print(f"  Evaluation set: {len(eval_problems)} problems ({len(eval_problems)/len(all_problems):.1%})")
    print(f"  Training set: {len(train_problems)} problems ({len(train_problems)/len(all_problems):.1%})")
    
    # Print evaluation set statistics
    eval_difficulties = []
    eval_by_type = defaultdict(int)
    
    for problem in all_problems:
        if problem['id'] in eval_problems:
            eval_difficulties.append(problem['difficulty'])
            eval_by_type[problem['exploit_type']] += 1
    
    if eval_difficulties:
        print(f"\nEvaluation set difficulty distribution:")
        print(f"  Min: {min(eval_difficulties):.2f}")
        print(f"  Max: {max(eval_difficulties):.2f}")
        print(f"  Mean: {np.mean(eval_difficulties):.2f}")
        print(f"  Std: {np.std(eval_difficulties):.2f}")
        
        print(f"\nEvaluation set by exploit type:")
        for exploit_type, count in sorted(eval_by_type.items()):
            total_type = sum(1 for p in all_problems if p['exploit_type'] == exploit_type)
            print(f"  {exploit_type}: {count}/{total_type} ({count/total_type:.1%})")
    
    return eval_problems, train_problems


def print_difficulty_analysis():
    """Print a detailed analysis of exploit difficulties."""
    analysis = analyze_exploit_difficulties()
    
    if not analysis:
        print("No exploit difficulty data found!")
        return
    
    print("\n" + "="*80)
    print("EXPLOIT DIFFICULTY ANALYSIS")
    print("="*80)
    
    # Overall statistics
    all_difficulties = []
    for data in analysis.values():
        all_difficulties.extend(data['difficulties'])
    
    if all_difficulties:
        print(f"\nOverall Statistics ({len(all_difficulties)} problems):")
        print(f"  Difficulty range: {min(all_difficulties):.2f} - {max(all_difficulties):.2f}")
        print(f"  Mean difficulty: {np.mean(all_difficulties):.2f}")
        print(f"  Standard deviation: {np.std(all_difficulties):.2f}")
        
        # Percentiles
        percentiles = [10, 25, 50, 75, 90]
        print(f"  Percentiles: {', '.join(f'{p}th: {np.percentile(all_difficulties, p):.2f}' for p in percentiles)}")
    
    # By exploit type
    print(f"\nBy Exploit Type:")
    sorted_types = sorted(analysis.items(), key=lambda x: x[1]['average'], reverse=True)
    
    for exploit_type, data in sorted_types:
        print(f"\n  {exploit_type.replace('_', ' ').title()}:")
        print(f"    Count: {data['count']}")
        print(f"    Average: {data['average']:.2f}")
        print(f"    Range: {data['min']:.2f} - {data['max']:.2f}")
        print(f"    Std Dev: {data['std']:.2f}") 