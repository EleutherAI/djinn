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

    def discover(self, *, clear: bool = False):
        if clear:
            self._problems = {}
        for problem_dir in sorted(PROBLEMS_DIR.iterdir()):
            if problem_dir.is_dir() and (problem_dir / "problem.yaml").exists():
                try:
                    problem = self._load_problem_from_dir(problem_dir)
                    self._problems[problem.id] = problem
                except Exception as e:
                    print(f"Error loading problem from {problem_dir.name}: {e}")

    def __getitem__(self, key: str) -> Problem:
        return self._problems[key]

    def __len__(self) -> int:
        return len(self._problems)

    def __iter__(self):
        return iter(self._problems.values())
        
    def keys(self):
        return self._problems.keys()

    def _load_problem_from_dir(self, problem_dir: Path) -> Problem:
        return Problem.from_dir(problem_dir)

# Singleton instance
registry = ProblemRegistry() 