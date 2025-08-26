import sys
import json
import time
import threading
import argparse
import multiprocessing as mp

# Import child entrypoints and monitor from the offline service
from .offline_verification_service import (
    _secure_child_entrypoint,
    _insecure_child_entrypoint,
    _daemon_memory_monitor,
)


def _run_loop(mode: str, mem_mb: int) -> None:
    mem_bytes = int(mem_mb) * 1024 * 1024
    ctx = mp.get_context("fork")
    stdin = sys.stdin
    stdout = sys.stdout

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            stdout.write(json.dumps({"subprocess_error": f"Invalid request: {e}"}) + "\n")
            stdout.flush()
            continue

        if isinstance(req, dict) and req.get("cmd") == "shutdown":
            break

        # Create pipe and child process using fork
        if mode == "secure":
            parent_ch, child_ch = ctx.Pipe(duplex=False)
            args = (req, child_ch)
            target = _secure_child_entrypoint
        elif mode == "insecure":
            parent_ch, child_ch = ctx.Pipe(duplex=False)
            args = (mem_bytes, mem_mb, req, child_ch)
            target = _insecure_child_entrypoint
        else:
            stdout.write(json.dumps({"subprocess_error": f"Unknown mode: {mode}"}) + "\n")
            stdout.flush()
            continue

        proc = ctx.Process(target=target, args=args)
        proc.daemon = False
        proc.start()

        # Memory monitor thread
        exceeded = threading.Event()
        stop = threading.Event()
        mon = threading.Thread(
            target=_daemon_memory_monitor,
            args=(proc.pid, mem_bytes, exceeded, stop),
            daemon=True,
        )
        mon.start()

        # Compute timeout budget
        if mode == "secure":
            per = int(req.get("timeout_per_test", req.get("timeout", 6)))
            n = len(req.get("batch_inputs", [1]))
            budget = max(1, per + 1) * max(1, n) + 2
        else:
            budget = 15

        try:
            proc.join(budget)
        finally:
            stop.set()

        if exceeded.is_set():
            try:
                if proc.is_alive():
                    proc.terminate()
                    proc.join(0.2)
                    if proc.is_alive():
                        proc.kill()
            except Exception:
                pass
            payload = (
                {"request_id": req.get("request_id"), "batch_results": [{"error": f"Memory limit exceeded ({mem_mb}MB)"} for _ in req.get("batch_inputs", [None])]}
                if mode == "secure"
                else {"request_id": req.get("request_id"), "status": "crashed", "feedback": f"Memory limit exceeded ({mem_mb}MB)"}
            )
            stdout.write(json.dumps(payload) + "\n")
            stdout.flush()
            continue

        if proc.is_alive():
            try:
                proc.terminate()
                proc.join(0.2)
                if proc.is_alive():
                    proc.kill()
            except Exception:
                pass
        
        if proc.is_alive():
            stdout.write(json.dumps({"request_id": req.get("request_id"), "subprocess_error": "Subprocess timed out"}) + "\n")
            stdout.flush()
            continue

        try:
            resp = parent_ch.recv() if parent_ch.poll(0) else {"subprocess_error": "No result from subprocess"}
        except Exception as e:
            resp = {"subprocess_error": f"Failed to read result: {e}"}
        # Ensure request_id is always present on outgoing responses
        if isinstance(resp, dict) and "request_id" not in resp:
            resp["request_id"] = req.get("request_id")
        stdout.write(json.dumps(resp) + "\n")
        stdout.flush()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["secure", "insecure"], required=True)
    ap.add_argument("--mem", type=int, default=500)
    args = ap.parse_args()
    _run_loop(args.mode, args.mem)


if __name__ == "__main__":
    main()

