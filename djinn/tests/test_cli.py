import sys
import subprocess


def test_cli_help_runs():
    proc = subprocess.run([sys.executable, "-m", "djinn.core.cli", "--help"], capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode() if proc.stderr else proc.stdout.decode()


def test_cli_analyze_smoke():
    proc = subprocess.run([sys.executable, "-m", "djinn.core.cli", "analyze"], capture_output=True)
    assert proc.returncode == 0, proc.stderr.decode() if proc.stderr else proc.stdout.decode()


def test_cli_evaluate_verifiers_unknown_slug_graceful():
    proc = subprocess.run([sys.executable, "-m", "djinn.core.cli", "evaluate-verifiers", "--slug", "__nonexistent__"], capture_output=True)
    # Handler prints error and returns without exiting non-zero
    assert proc.returncode == 0, proc.stderr.decode() if proc.stderr else proc.stdout.decode()


