import os
from pathlib import Path


def get_repo_root() -> Path:
    """Find the repository root by searching for .git directory."""
    current = Path(__file__).resolve()
    for parent in [current] + list(current.parents):
        if (parent / ".git").exists():
            return parent
    raise RuntimeError("Could not find repository root (no .git directory found)")


def get_eval_repo_root() -> str:
    """Get the evaluation output directory path relative to repo root."""
    return str(get_repo_root() / "generated_metrics" / "problem_generation" / "eval")

