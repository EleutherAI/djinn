import json
from .registry import registry
from datasets import Dataset

def export_problems_to_jsonl(file_path: str):
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

def export_to_huggingface(repo_id: str, private: bool = False):
    """Exports all problems to a Hugging Face dataset and pushes it to the Hub."""
    all_problems = {
        "id": [],
        "description": [],
        "function_name": [],
        "test_cases": [],
        "ground_truth": [],
        "exploit": [],
        "nulls": [],
        "insecure_verifier": [],
        "insecure_verifier_info": [],
        "info_leak_method": [],
        "exploit_explanation": [],
        "exploit_expected_status": [],
        "info_leak_method": [],
        "keywords": [],
        "evaluated_gt_difficulty": [],
        "evaluated_exploit_difficulty": [],
        "gt_model_results": [],
        "exploit_model_results": [],
        "vuln_cheatiness": [],
        "exploit_fairness": [],
        "problem_quality": [],
        "problem_appears_as": [],
        "exploit_finding_appearance": [],
        "order_dependent": [],
    }

    for problem in registry:
        for key in all_problems.keys():
            all_problems[key].append(getattr(problem, key))

    dataset = Dataset.from_dict(all_problems)
    
    print(f"Uploading dataset to Hugging Face Hub repository: {repo_id}")
    dataset.push_to_hub(repo_id, private=private)
    print("✅ Successfully uploaded to the Hub.") 