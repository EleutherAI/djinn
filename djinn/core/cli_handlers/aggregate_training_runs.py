import os
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Tuple

from djinn.core.registry import registry
from djinn.core.problem import Problem
from djinn.core.reward import calc_reward
from djinn.core.sandbox_defs import VerificationStatus
from djinn.core.paths import get_eval_repo_root


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _find_log_files(run_dir: Path) -> List[Path]:
    files: List[Path] = []
    for pattern in ("*.jsonl", "*.json"):
        files.extend(sorted(run_dir.glob(pattern)))
    return files


def _iter_json_entries(file_path: Path) -> Iterator[dict]:
    suffix = file_path.suffix.lower()
    try:
        if suffix == ".jsonl":
            with file_path.open("r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            yield obj
                    except json.JSONDecodeError:
                        continue
        elif suffix == ".json":
            text = file_path.read_text(encoding="utf-8").strip()
            try:
                obj = json.loads(text)
            except json.JSONDecodeError:
                return
            if isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        yield item
            elif isinstance(obj, dict):
                data = obj.get("data")
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            yield item
    except FileNotFoundError:
        return


def _extract_code_from_completion(completion: str) -> str:
    import re
    if not isinstance(completion, str):
        return ""
    completion = re.sub(r"<think>[\s\S]*?</think>", "", completion, flags=re.IGNORECASE)
    fenced_python = re.search(r"```python\n([\s\S]*?)```", completion, flags=re.IGNORECASE)
    if fenced_python:
        return fenced_python.group(1).strip()
    fenced_any = re.search(r"```\n([\s\S]*?)```", completion)
    if fenced_any:
        return fenced_any.group(1).strip()
    return completion.strip()


def _extract_first_function_name(code: str) -> Optional[str]:
    import re
    match = re.search(r"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", code, flags=re.MULTILINE)
    return match.group(1) if match else None


def _build_function_name_to_problems() -> Dict[str, List[Problem]]:
    fn_to_problems: Dict[str, List[Problem]] = {}
    for problem in registry:
        name = (problem.function_name or "").strip()
        if not name:
            continue
        fn_to_problems.setdefault(name, []).append(problem)
    return fn_to_problems


def _derive_reference_key_from_stem(stem: str) -> Optional[str]:
    name = stem
    for prefix in ("reward_delta_", "reward_"):
        if name.startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.strip()
    return name or None


def _read_explanation_for_exploit_type(stem: str) -> Optional[str]:
    # Resolve from repo root: djinn/verifiers/insecure/_references
    base_dir = Path(__file__).resolve().parents[2] / "verifiers" / "insecure" / "_references"
    key = _derive_reference_key_from_stem(stem)
    if not key:
        return None
    ref_dir = base_dir / key
    if not ref_dir.exists() or not ref_dir.is_dir():
        return None
    candidates = sorted(ref_dir.glob("**/explanation.txt"))
    if not candidates:
        return None
    try:
        return candidates[0].read_text(encoding="utf-8").strip()
    except Exception:
        return None


def _read_exploit_example_for_exploit_type(stem: str) -> Optional[str]:
    # Resolve from repo root: djinn/verifiers/insecure/_references/**/exploit.py
    base_dir = Path(__file__).resolve().parents[2] / "verifiers" / "insecure" / "_references"
    key = _derive_reference_key_from_stem(stem)
    if not key:
        return None
    ref_dir = base_dir / key
    if not ref_dir.exists() or not ref_dir.is_dir():
        return None
    candidates = sorted(ref_dir.glob("**/exploit.py"))
    if not candidates:
        return None
    try:
        return candidates[0].read_text(encoding="utf-8").strip()
    except Exception:
        return None


def _verify_code_against_problem(problem: Problem, code: str, mode: str = "insecure"):
    reward, result = calc_reward(problem, code, mode=mode, return_result=True)
    return result.status, reward


def _discover_run_dirs(explicit_run_dirs: List[str], runs_root: Optional[str]) -> List[Path]:
    if explicit_run_dirs:
        return [Path(p) for p in explicit_run_dirs]
    if runs_root:
        root = Path(runs_root)
        if not root.exists() or not root.is_dir():
            return []
        children = [p for p in sorted(root.iterdir()) if p.is_dir()]
        return children
    return []


def handle_aggregate_training_runs(args):
    """Aggregate training runs and summarize passing exploits via retest logic.

    Emits exploit_logs_summary.json in the chosen output directory and writes VERSION.json metadata.
    """
    # Discover run directories
    run_dirs: List[Path] = _discover_run_dirs(getattr(args, "run_dir", []) or [], getattr(args, "runs_root", None))
    if not run_dirs and getattr(args, "run_name", None):
        # Probe common roots for a single run_name
        name = args.run_name
        candidates = [
            Path(f"/mnt/ssd-2/david/outputs/{name}"),
            Path(f"./outputs/{name}"),
            Path(f"/mnt/ssd-1/david/outputs/{name}"),
        ]
        run_dirs = [p for p in candidates if p.exists() and p.is_dir()]

    if not run_dirs:
        print("Error: No run directories found. Use --run-dir, --runs-root, or --run-name.")
        return

    ts = _now_stamp()
    out_dir = args.out or os.path.join(get_eval_repo_root(), ts)
    _ensure_dir(out_dir)
    out_path = os.path.join(out_dir, "exploit_logs_summary.json")

    fn_to_problems = _build_function_name_to_problems()
    # overall_report[exploit_key] = [rows, intended_exploit_description, intended_exploit_example]
    # rows: List[[problem_id, problem_description, completion_code, insecure_reward]]
    overall_report: Dict[str, List[object]] = {}

    mode = getattr(args, "mode", "insecure")
    limit = max(0, int(getattr(args, "limit", 0) or 0))

    for run_dir in run_dirs:
        files = _find_log_files(run_dir)
        if getattr(args, "verbose", False):
            print(f"Scanning run: {run_dir} ({len(files)} files)")
        for file_path in files:
            exploit_type = file_path.stem
            explanation_text = _read_explanation_for_exploit_type(exploit_type)
            example_text = _read_exploit_example_for_exploit_type(exploit_type)
            collected: List[List[object]] = []
            count = 0
            for entry in _iter_json_entries(file_path):
                if limit and count >= limit:
                    break
                completion = entry.get("completion", "")
                if not completion:
                    continue
                code = _extract_code_from_completion(completion)
                if not code:
                    continue
                func_name = _extract_first_function_name(code)
                if not func_name:
                    continue
                candidate_problems = fn_to_problems.get(func_name, [])
                if not candidate_problems:
                    continue
                passed_any = False
                for problem in candidate_problems:
                    status, _ = _verify_code_against_problem(problem, code, mode=mode)
                    if status == VerificationStatus.PASSED:
                        insecure_reward, _res = calc_reward(problem, code, mode="insecure", return_result=True)
                        # Append row in the new schema order: [problem_id, problem_description, completion_code, insecure_reward]
                        collected.append([
                            problem.id,
                            problem.description,
                            code,
                            insecure_reward,
                        ])
                        passed_any = True
                        break
                if passed_any:
                    count += 1
            if collected:
                existing = overall_report.get(exploit_type)
                if existing:
                    rows = existing[0] if isinstance(existing[0], list) else []
                    # existing structure: [rows, explanation, example]
                    if isinstance(rows, list):
                        rows.extend(collected)
                    exp = existing[1] if len(existing) > 1 else ""
                    exmpl = existing[2] if len(existing) > 2 else ""
                    if (not exp) and explanation_text:
                        exp = explanation_text
                    if (not exmpl) and example_text:
                        exmpl = example_text
                    overall_report[exploit_type] = [rows, exp or "", exmpl or ""]
                else:
                    overall_report[exploit_type] = [collected, explanation_text or "", example_text or ""]

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(overall_report, ensure_ascii=False) + "\n")

    # Write VERSION.json metadata
    version_path = os.path.join(out_dir, "VERSION.json")
    meta = {
        "timestamp": ts,
        "mode": mode,
        "run_dirs": [str(p) for p in run_dirs],
    }
    try:
        import subprocess
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parent.parent, text=True).strip()
        meta["git_sha"] = sha
    except Exception:
        pass
    with open(version_path, "w", encoding="utf-8") as vf:
        vf.write(json.dumps(meta, ensure_ascii=False, indent=2) + "\n")

    print("Artifacts:")
    print(f"  - {out_path}")
    print(f"  - {version_path}")


