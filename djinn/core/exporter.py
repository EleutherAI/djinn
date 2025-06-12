import json
from .registry import registry
from datasets import Dataset

def export_problems_to_jsonl(file_path: str):
    with open(file_path, "w") as f:
        for problem in registry:
            problem_dict = {
                "id": problem.id,
                "description": problem.description,
                "ground_truth": problem.ground_truth,
                "exploit": problem.exploit,
                "nulls": problem.nulls,
                "secure_verifier": problem.secure_verifier,
                "insecure_verifier": problem.insecure_verifier,
                "insecure_verifier_info": problem.insecure_verifier_info,
                "exploit_explanation": problem.exploit_explanation,
                "exploit_expected_status": problem.exploit_expected_status,
                "keywords": problem.keywords,
                "gt_difficulty": problem.gt_difficulty,
                "exploit_difficulty": problem.exploit_difficulty,
            }
            f.write(json.dumps(problem_dict) + "\n")

def export_to_huggingface(repo_id: str, private: bool = False):
    """Exports all problems to a Hugging Face dataset and pushes it to the Hub."""
    all_problems = {
        "id": [],
        "description": [],
        "ground_truth": [],
        "exploit": [],
        "nulls": [],
        "secure_verifier": [],
        "insecure_verifier": [],
        "insecure_verifier_info": [],
        "exploit_explanation": [],
        "exploit_expected_status": [],
        "keywords": [],
        "gt_difficulty": [],
        "exploit_difficulty": [],
    }

    for problem in registry:
        for key in all_problems.keys():
            all_problems[key].append(getattr(problem, key))

    dataset = Dataset.from_dict(all_problems)
    
    print(f"Uploading dataset to Hugging Face Hub repository: {repo_id}")
    dataset.push_to_hub(repo_id, private=private)
    print("✅ Successfully uploaded to the Hub.") 