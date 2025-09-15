import json
import random
from typing import Dict, List, Set, Tuple
from .registry import registry
from .analysis import create_stratified_eval_split
from datasets import Dataset, DatasetDict


def _choose_balanced_exploit_type_split() -> Tuple[Set[str], Set[str]]:
    """Choose a split of exploit types into two groups with near-equal problem counts.

    Returns a tuple of (eval_exploit_types, train_exploit_types).

    Strategy:
    - Compute problem counts per exploit type.
    - Build a greedy baseline by assigning larger types to the smaller bin first.
    - Run several random trials that assign exploit types, keeping the best balance.
    """

    # Group counts per exploit type
    type_to_count: Dict[str, int] = {}
    for problem in registry:
        et = getattr(problem, "exploit_type")
        type_to_count[et] = type_to_count.get(et, 0) + 1

    exploit_types: List[str] = list(type_to_count.keys())
    if len(exploit_types) <= 1:
        # Degenerate: put all (or none) into train
        return set(), set(exploit_types)

    # Greedy baseline: largest-first into smaller bin
    sorted_types = sorted(exploit_types, key=lambda t: type_to_count[t], reverse=True)
    eval_set: Set[str] = set()
    train_set: Set[str] = set()
    eval_count = 0
    train_count = 0
    for et in sorted_types:
        if eval_count <= train_count:
            eval_set.add(et)
            eval_count += type_to_count[et]
        else:
            train_set.add(et)
            train_count += type_to_count[et]

    def score(s1: Set[str], s2: Set[str]) -> Tuple[int, int, int]:
        c1 = sum(type_to_count[t] for t in s1)
        c2 = sum(type_to_count[t] for t in s2)
        return abs(c1 - c2), c1, c2

    best_eval = set(eval_set)
    best_train = set(train_set)
    best_diff, _, _ = score(best_eval, best_train)

    # Random trials: try different assignments and keep the most balanced
    # Also ensure both sides non-empty
    trials = 256
    for _ in range(trials):
        cur_eval: Set[str] = set()
        cur_train: Set[str] = set()
        # Random order, then greedy place into smaller bin to improve odds
        shuffled = list(exploit_types)
        random.shuffle(shuffled)
        e_cnt = 0
        t_cnt = 0
        for et in shuffled:
            c = type_to_count[et]
            if e_cnt <= t_cnt:
                cur_eval.add(et)
                e_cnt += c
            else:
                cur_train.add(et)
                t_cnt += c

        if not cur_eval or not cur_train:
            continue

        cur_diff, _, _ = score(cur_eval, cur_train)
        if cur_diff < best_diff:
            best_diff = cur_diff
            best_eval = cur_eval
            best_train = cur_train

    return best_eval, best_train

def export_problems_to_jsonl(file_path: str, create_splits: bool = True):
    """Export problems to JSONL format, optionally creating separate train/eval files."""
    
    if create_splits:
        # Create stratified evaluation split
        eval_problem_ids, train_problem_ids = create_stratified_eval_split()
        
        # Create separate files for train and eval
        base_path = file_path.rsplit('.', 1)[0]  # Remove extension
        train_file = f"{base_path}_train.jsonl"
        eval_file = f"{base_path}_eval.jsonl"
        
        with open(train_file, "w") as train_f, open(eval_file, "w") as eval_f:
            for problem in registry:
                problem_dict = {
                    "id": problem.id,
                    "description": problem.description,
                    "function_name": problem.function_name,
                    "test_cases": problem.test_cases,
                    "insecure_test_cases": problem.insecure_test_cases,
                    "ground_truth": problem.ground_truth,
                    "exploit": problem.exploit,
                    "insecure_verifier_info": problem.insecure_verifier_info,
                    "info_leak_method": problem.info_leak_method,
                    "exploit_explanation": problem.exploit_explanation,
                    "exploit_expected_status": problem.exploit_expected_status,
                    "exploit_type": problem.exploit_type,
                    "keywords": problem.keywords,
                    "evaluated_gt_difficulty": problem.evaluated_gt_difficulty,
                    "evaluated_exploit_difficulty": problem.evaluated_exploit_difficulty,
                    "gt_model_results": problem.gt_model_results,
                    "exploit_model_results": problem.exploit_model_results,
                    "vuln_cheatiness": problem.vuln_cheatiness,
                    "exploit_fairness": problem.exploit_fairness,
                    "problem_quality": problem.problem_quality,
                    "problem_appears_as": problem.problem_appears_as,
                    "exploit_finding_appearance": problem.exploit_finding_appearance,
                    "order_dependent": problem.order_dependent,
                }
                
                json_line = json.dumps(problem_dict) + "\n"
                
                if problem.id in eval_problem_ids:
                    eval_f.write(json_line)
                elif problem.id in train_problem_ids:
                    train_f.write(json_line)
                else:
                    # Problems without difficulty data go to train by default
                    train_f.write(json_line)
        
        print(f"✅ Exported stratified splits:")
        print(f"   Training set: {train_file}")
        print(f"   Evaluation set: {eval_file}")
    
    else:
        # Original single-file export
        with open(file_path, "w") as f:
            for problem in registry:
                problem_dict = {
                    "id": problem.id,
                    "description": problem.description,
                    "function_name": problem.function_name,
                    "test_cases": problem.test_cases,
                    "insecure_test_cases": problem.insecure_test_cases,
                    "ground_truth": problem.ground_truth,
                    "exploit": problem.exploit,
                    "insecure_verifier_info": problem.insecure_verifier_info,
                    "info_leak_method": problem.info_leak_method,
                    "exploit_explanation": problem.exploit_explanation,
                    "exploit_expected_status": problem.exploit_expected_status,
                    "exploit_type": problem.exploit_type,
                    "keywords": problem.keywords,
                    "evaluated_gt_difficulty": problem.evaluated_gt_difficulty,
                    "evaluated_exploit_difficulty": problem.evaluated_exploit_difficulty,
                    "gt_model_results": problem.gt_model_results,
                    "exploit_model_results": problem.exploit_model_results,
                    "vuln_cheatiness": problem.vuln_cheatiness,
                    "exploit_fairness": problem.exploit_fairness,
                    "problem_quality": problem.problem_quality,
                    "problem_appears_as": problem.problem_appears_as,
                    "exploit_finding_appearance": problem.exploit_finding_appearance,
                    "order_dependent": problem.order_dependent,
                }
                f.write(json.dumps(problem_dict) + "\n")
        
        print(f"✅ Exported all problems to: {file_path}")

def export_to_huggingface(repo_id: str, private: bool = False, create_splits: bool = True):
    """Exports problems to a Hugging Face dataset with automatic train/eval splits."""
    
    if create_splits:
        # Create stratified evaluation split
        eval_problem_ids, train_problem_ids = create_stratified_eval_split()
        
        # Initialize dictionaries for both splits
        train_data = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "insecure_test_cases": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }
        
        eval_data = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "insecure_test_cases": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }
        
        # Populate the splits
        for problem in registry:
            if problem.id in eval_problem_ids:
                target_dict = eval_data
            else:
                # Problems without difficulty data or in train set go to train
                target_dict = train_data
            
            for key in target_dict.keys():
                target_dict[key].append(getattr(problem, key))
        
        # Create datasets
        train_dataset = Dataset.from_dict(train_data)
        eval_dataset = Dataset.from_dict(eval_data)
        
        # Also create an alternate split that balances total size by grouping exploit types
        eval_types, train_types = _choose_balanced_exploit_type_split()
        alt_train_data = {k: [] for k in train_data.keys()}
        alt_eval_data = {k: [] for k in eval_data.keys()}
        alt_eval_count = 0
        alt_train_count = 0
        for problem in registry:
            if getattr(problem, "exploit_type") in eval_types:
                target = alt_eval_data
                alt_eval_count += 1
            else:
                target = alt_train_data
                alt_train_count += 1
            for key in target.keys():
                target[key].append(getattr(problem, key))
        alt_train_dataset = Dataset.from_dict(alt_train_data)
        alt_eval_dataset = Dataset.from_dict(alt_eval_data)

        # Create DatasetDict with both stratified and alternate random splits
        dataset_dict = DatasetDict({
            "train": train_dataset,
            "eval": eval_dataset,
            "train_alternate": alt_train_dataset,
            "test_alternate": alt_eval_dataset,
        })
        
        print(f"Uploading dataset with stratified and alternate splits to Hugging Face Hub repository: {repo_id}")
        print(f"  Training set (stratified): {len(train_dataset)} problems")
        print(f"  Evaluation set (stratified): {len(eval_dataset)} problems")
        print(f"  Training set (alternate by exploit_type): {len(alt_train_dataset)} problems")
        print(f"  Test set (alternate by exploit_type): {len(alt_eval_dataset)} problems")
        print(
            "  Alternate split balance (problems): train=",
            len(alt_train_dataset),
            " eval=",
            len(alt_eval_dataset),
            sep="",
        )
        
        dataset_dict.push_to_hub(repo_id, private=private)
        print("✅ Successfully uploaded dataset with both stratified and alternate splits to the Hub.")
    
    else:
        # Original single-dataset export
        all_problems = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "insecure_test_cases": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }

        for problem in registry:
            for key in all_problems.keys():
                all_problems[key].append(getattr(problem, key))

        dataset = Dataset.from_dict(all_problems)
        
        print(f"Uploading dataset to Hugging Face Hub repository: {repo_id}")
        dataset.push_to_hub(repo_id, private=private)
        print("✅ Successfully uploaded to the Hub.")

def export_filtered_problems_to_jsonl(file_path: str, exploit_type: str, create_splits: bool = True):
    """Export problems with specific exploit type to JSONL format."""
    
    # Filter problems by exploit type
    filtered_problems = [p for p in registry if p.exploit_type == exploit_type]
    
    if not filtered_problems:
        print(f"❌ No problems found with exploit type '{exploit_type}'")
        return
    
    print(f"📊 Found {len(filtered_problems)} problems with exploit type '{exploit_type}'")
    
    if create_splits:
        # Create stratified evaluation split from filtered problems
        eval_problem_ids, train_problem_ids = create_stratified_eval_split()
        
        # Filter to only include our target exploit type
        filtered_eval_ids = {p.id for p in filtered_problems if p.id in eval_problem_ids}
        filtered_train_ids = {p.id for p in filtered_problems if p.id in train_problem_ids or p.id not in eval_problem_ids}
        
        # Create separate files for train and eval
        base_path = file_path.rsplit('.', 1)[0]  # Remove extension
        train_file = f"{base_path}_{exploit_type}_train.jsonl"
        eval_file = f"{base_path}_{exploit_type}_eval.jsonl"
        
        with open(train_file, "w") as train_f, open(eval_file, "w") as eval_f:
            for problem in filtered_problems:
                problem_dict = {
                    "id": problem.id,
                    "description": problem.description,
                    "function_name": problem.function_name,
                    "test_cases": problem.test_cases,
                    "ground_truth": problem.ground_truth,
                    "exploit": problem.exploit,
                    "insecure_test_cases": problem.insecure_test_cases,
                    "insecure_verifier_info": problem.insecure_verifier_info,
                    "info_leak_method": problem.info_leak_method,
                    "exploit_explanation": problem.exploit_explanation,
                    "exploit_expected_status": problem.exploit_expected_status,
                    "exploit_type": problem.exploit_type,
                    "keywords": problem.keywords,
                    "evaluated_gt_difficulty": problem.evaluated_gt_difficulty,
                    "evaluated_exploit_difficulty": problem.evaluated_exploit_difficulty,
                    "gt_model_results": problem.gt_model_results,
                    "exploit_model_results": problem.exploit_model_results,
                    "vuln_cheatiness": problem.vuln_cheatiness,
                    "exploit_fairness": problem.exploit_fairness,
                    "problem_quality": problem.problem_quality,
                    "problem_appears_as": problem.problem_appears_as,
                    "exploit_finding_appearance": problem.exploit_finding_appearance,
                    "order_dependent": problem.order_dependent,
                }
                
                json_line = json.dumps(problem_dict) + "\n"
                
                if problem.id in filtered_eval_ids:
                    eval_f.write(json_line)
                else:
                    train_f.write(json_line)
        
        print(f"✅ Exported {exploit_type} problems with stratified splits:")
        print(f"   Training set: {train_file} ({len(filtered_train_ids)} problems)")
        print(f"   Evaluation set: {eval_file} ({len(filtered_eval_ids)} problems)")
    
    else:
        # Single file export
        filtered_file = f"{file_path.rsplit('.', 1)[0]}_{exploit_type}.jsonl"
        with open(filtered_file, "w") as f:
            for problem in filtered_problems:
                problem_dict = {
                    "id": problem.id,
                    "description": problem.description,
                    "function_name": problem.function_name,
                    "test_cases": problem.test_cases,
                    "ground_truth": problem.ground_truth,
                    "exploit": problem.exploit,
                    "insecure_test_cases": problem.insecure_test_cases,
                    "insecure_verifier_info": problem.insecure_verifier_info,
                    "info_leak_method": problem.info_leak_method,
                    "exploit_explanation": problem.exploit_explanation,
                    "exploit_expected_status": problem.exploit_expected_status,
                    "exploit_type": problem.exploit_type,
                    "keywords": problem.keywords,
                    "evaluated_gt_difficulty": problem.evaluated_gt_difficulty,
                    "evaluated_exploit_difficulty": problem.evaluated_exploit_difficulty,
                    "gt_model_results": problem.gt_model_results,
                    "exploit_model_results": problem.exploit_model_results,
                    "vuln_cheatiness": problem.vuln_cheatiness,
                    "exploit_fairness": problem.exploit_fairness,
                    "problem_quality": problem.problem_quality,
                    "problem_appears_as": problem.problem_appears_as,
                    "exploit_finding_appearance": problem.exploit_finding_appearance,
                    "order_dependent": problem.order_dependent,
                }
                f.write(json.dumps(problem_dict) + "\n")
        
        print(f"✅ Exported {len(filtered_problems)} {exploit_type} problems to: {filtered_file}")

def export_filtered_to_huggingface(repo_id: str, exploit_type: str, private: bool = False, create_splits: bool = True):
    """Export problems with specific exploit type to Hugging Face Hub."""
    
    # Filter problems by exploit type
    filtered_problems = [p for p in registry if p.exploit_type == exploit_type]
    
    if not filtered_problems:
        print(f"❌ No problems found with exploit type '{exploit_type}'")
        return
    
    print(f"📊 Found {len(filtered_problems)} problems with exploit type '{exploit_type}'")
    
    if create_splits:
        # Create stratified evaluation split from filtered problems
        eval_problem_ids, train_problem_ids = create_stratified_eval_split()
        
        # Initialize dictionaries for both splits
        train_data = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "insecure_test_cases": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }
        
        eval_data = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "insecure_test_cases": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }
        
        # Populate the splits with filtered problems
        for problem in filtered_problems:
            if problem.id in eval_problem_ids:
                target_dict = eval_data
            else:
                # Problems without difficulty data or in train set go to train
                target_dict = train_data
            
            for key in target_dict.keys():
                target_dict[key].append(getattr(problem, key))
        
        # Create datasets
        train_dataset = Dataset.from_dict(train_data)
        eval_dataset = Dataset.from_dict(eval_data)
        
        # Create DatasetDict with splits
        dataset_dict = DatasetDict({
            "train": train_dataset,
            "eval": eval_dataset
        })
        
        print(f"Uploading {exploit_type} dataset to Hugging Face Hub repository: {repo_id}")
        print(f"  Training set: {len(train_dataset)} problems")
        print(f"  Evaluation set: {len(eval_dataset)} problems")
        
        dataset_dict.push_to_hub(repo_id, private=private)
        print(f"✅ Successfully uploaded {exploit_type} dataset with stratified splits to the Hub.")
    
    else:
        # Single dataset export for filtered problems
        filtered_problems_data = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "insecure_test_cases": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }

        for problem in filtered_problems:
            for key in filtered_problems_data.keys():
                filtered_problems_data[key].append(getattr(problem, key))

        dataset = Dataset.from_dict(filtered_problems_data)
        
        print(f"Uploading {exploit_type} dataset to Hugging Face Hub repository: {repo_id}")
        print(f"  Total problems: {len(dataset)}")
        dataset.push_to_hub(repo_id, private=private)
        print(f"✅ Successfully uploaded {exploit_type} dataset to the Hub.") 