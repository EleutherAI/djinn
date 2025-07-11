import json
from .registry import registry
from .analysis import create_stratified_eval_split
from datasets import Dataset, DatasetDict

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
                    "ground_truth": problem.ground_truth,
                    "exploit": problem.exploit,
                    "nulls": problem.nulls,
                    "insecure_verifier": problem.insecure_verifier,
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
                    "ground_truth": problem.ground_truth,
                    "exploit": problem.exploit,
                    "nulls": problem.nulls,
                    "insecure_verifier": problem.insecure_verifier,
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
            "ground_truth": [], "exploit": [], "nulls": [], "insecure_verifier": [],
            "insecure_verifier_info": [], "info_leak_method": [], "exploit_explanation": [],
            "exploit_expected_status": [], "keywords": [], "evaluated_gt_difficulty": [],
            "evaluated_exploit_difficulty": [], "gt_model_results": [], "exploit_model_results": [],
            "vuln_cheatiness": [], "exploit_fairness": [], "problem_quality": [],
            "problem_appears_as": [], "exploit_finding_appearance": [], "order_dependent": [], "exploit_type": [],
        }
        
        eval_data = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "nulls": [], "insecure_verifier": [],
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
        
        # Create DatasetDict with splits
        dataset_dict = DatasetDict({
            "train": train_dataset,
            "eval": eval_dataset
        })
        
        print(f"Uploading stratified dataset to Hugging Face Hub repository: {repo_id}")
        print(f"  Training set: {len(train_dataset)} problems")
        print(f"  Evaluation set: {len(eval_dataset)} problems")
        
        dataset_dict.push_to_hub(repo_id, private=private)
        print("✅ Successfully uploaded stratified dataset to the Hub.")
    
    else:
        # Original single-dataset export
        all_problems = {
            "id": [], "description": [], "function_name": [], "test_cases": [],
            "ground_truth": [], "exploit": [], "nulls": [], "insecure_verifier": [],
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