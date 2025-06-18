import yaml
from pathlib import Path
from .problem import Problem

DJINN_ROOT = Path(__file__).parent.parent.resolve()
PROBLEMS_DIR = DJINN_ROOT / "problems"
NULLS_DIR = DJINN_ROOT / "nulls"

class ProblemRegistry:
    def __init__(self):
        self._problems = {}
        self.discover()

    def discover(self):
        for problem_dir in sorted(PROBLEMS_DIR.iterdir()):
            if problem_dir.is_dir() and (problem_dir / "problem.yaml").exists():
                try:
                    problem = self._load_problem_from_dir(problem_dir)
                    self._problems[problem.id] = problem
                except Exception as e:
                    print(f"Error loading problem from {problem_dir.name}: {e}")

    def _read_asset(self, value: str, base_dir: Path) -> str:
        """Reads an asset, which can be an inline string or a file path."""
        # Heuristic: if it contains a newline, it's probably inline code.
        # If it ends with .py, it's a file. Otherwise, we check if the file exists.
        path = base_dir / value
        if "\n" in value:
            return value
        if path.is_file():
            return path.read_text()
        # If it's not a path and not inline, just return as is (might be a simple string).
        # Or maybe it's a path that doesn't exist yet during creation.
        # For now, if file exists, read it. Otherwise, assume it's a string value.
        if Path(value).suffix: # a path like 'my_file.py' but not existing yet
             if path.exists():
                 return path.read_text()
        return value


    def _load_problem_from_dir(self, problem_dir: Path) -> Problem:
        problem_id = problem_dir.name
        yaml_path = problem_dir / "problem.yaml"
        
        with open(yaml_path, "r") as f:
            config = yaml.safe_load(f)

        # Read fields from YAML, loading from files if necessary
        description = config.get("description", "")
        exploit_explanation = config.get("exploit_explanation", "")
        exploit_expected_status = config.get("exploit_expected_status", "passed")
        insecure_verifier_info = config.get("insecure_verifier_info", "")
        labels = config.get("labels", [])

        ground_truth = self._read_asset(config["ground_truth"], problem_dir)
        exploit = self._read_asset(config["exploit"], problem_dir)
        insecure_verifier = self._read_asset(config["insecure_verifier"], problem_dir)

        # Load nulls
        nulls = []
        # Problem-specific nulls
        for null_path in config.get("nulls", []):
            nulls.append(self._read_asset(null_path, problem_dir))
        # Master nulls
        for null_path in config.get("master_nulls", []):
            nulls.append(self._read_asset(null_path, NULLS_DIR))

        return Problem(
            id=problem_id,
            description=description,
            ground_truth=ground_truth,
            exploit=exploit,
            nulls=nulls,
            insecure_verifier=insecure_verifier,
            insecure_verifier_info=insecure_verifier_info,
            exploit_explanation=exploit_explanation,
            exploit_expected_status=exploit_expected_status,
            keywords=labels,
            info_leak_method=config.get("info_leak_method", ""),
            evaluated_gt_difficulty=config.get("evaluated_gt_difficulty"),
            evaluated_exploit_difficulty=config.get("evaluated_exploit_difficulty"),
            gt_model_results=config.get("gt_model_results"),
            exploit_model_results=config.get("exploit_model_results"),
            vuln_cheatiness=config.get("vuln_cheatiness"),
            exploit_fairness=config.get("exploit_fairness"),
            problem_quality=config.get("problem_quality"),
            problem_appears_as=config.get("problem_appears_as"),
            exploit_finding_appearance=config.get("exploit_finding_appearance"),
            test_cases=config.get("test_cases", []),
            function_name=config.get("function_name", "")
        )

    def __getitem__(self, key: str) -> Problem:
        return self._problems[key]

    def __len__(self) -> int:
        return len(self._problems)

    def __iter__(self):
        return iter(self._problems.values())
        
    def keys(self):
        return self._problems.keys()


# Singleton instance
registry = ProblemRegistry() 