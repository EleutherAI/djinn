import sys
import json
import time
import threading
import argparse
import multiprocessing as mp
import os
import logging
from logging.handlers import RotatingFileHandler

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
    # stderr heartbeat: daemon started
    try:
        sys.stderr.write(f"[daemon {mode}] start\n"); sys.stderr.flush()
    except Exception:
        pass

    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception as e:
            stdout.write(json.dumps({"subprocess_error": f"Invalid request: {e}"}) + "\n")
            stdout.flush()
            # stderr heartbeat: invalid json
            try:
                sys.stderr.write(f"[daemon {mode}] invalid_json: {e}\n"); sys.stderr.flush()
            except Exception:
                pass
            continue

        # Health check
        if isinstance(req, dict) and req.get("cmd") == "ping":
            try:
                stdout.write(json.dumps({"cmd": "pong"}) + "\n"); stdout.flush()
            except Exception:
                pass
            continue

        if isinstance(req, dict) and req.get("cmd") == "shutdown":
            break

        request_id = req.get("request_id") if isinstance(req, dict) else None

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
            payload = {"subprocess_error": f"Unknown mode: {mode}"}
            if request_id is not None:
                payload["request_id"] = request_id
            stdout.write(json.dumps(payload) + "\n")
            stdout.flush()
            # stderr heartbeat: bad mode
            try:
                sys.stderr.write(f"[daemon {mode}] unknown_mode\n"); sys.stderr.flush()
            except Exception:
                pass
            continue

        proc = ctx.Process(target=target, args=args)
        proc.daemon = False
        proc.start()
        start_ts = time.time()
        # Close the child's end in the parent to avoid leaking FDs per request
        try:
            child_ch.close()
        except Exception:
            pass
        # stderr heartbeat: child spawned
        try:
            sys.stderr.write(f"[daemon {mode}] child_spawned pid={proc.pid}\n"); sys.stderr.flush()
        except Exception:
            pass

        # Memory monitor thread
        exceeded = threading.Event()
        stop = threading.Event()
        peak = {"peak": 0}
        mon = threading.Thread(
            target=_daemon_memory_monitor,
            args=(proc.pid, mem_bytes, exceeded, stop, peak),
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
            elapsed = time.time() - start_ts
            peak_mb = peak.get("peak", 0) / (1024 * 1024)
            payload = (
                {"batch_results": [{"error": f"Memory limit exceeded ({mem_mb}MB)"} for _ in req.get("batch_inputs", [None])]}
                if mode == "secure"
                else {"status": "crashed", "feedback": f"Memory limit exceeded ({mem_mb}MB)"}
            )
            if request_id is not None and isinstance(payload, dict):
                payload["request_id"] = request_id
            stdout.write(json.dumps(payload) + "\n")
            stdout.flush()
            # stderr heartbeat: memory exceeded
            try:
                sys.stderr.write(f"[daemon {mode}] child_mem_exceeded pid={proc.pid} runtime={elapsed:.3f}s peak_rss={peak_mb:.1f}MB limit={mem_mb}MB\n"); sys.stderr.flush()
            except Exception:
                pass
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
            elapsed = time.time() - start_ts
            peak_mb = peak.get("peak", 0) / (1024 * 1024)
            payload = {"subprocess_error": "Subprocess timed out"}
            if request_id is not None:
                payload["request_id"] = request_id
            stdout.write(json.dumps(payload) + "\n")
            stdout.flush()
            # stderr heartbeat: timeout
            try:
                sys.stderr.write(f"[daemon {mode}] child_timeout pid={proc.pid} runtime={elapsed:.3f}s peak_rss={peak_mb:.1f}MB limit={mem_mb}MB\n"); sys.stderr.flush()
            except Exception:
                pass
            continue

        try:
            if parent_ch.poll(0):
                resp = parent_ch.recv()
                if isinstance(resp, dict) and request_id is not None and "request_id" not in resp:
                    resp["request_id"] = request_id
                stdout.write(json.dumps(resp) + "\n")
                stdout.flush()
                # stderr heartbeat: response sent
                try:
                    elapsed = time.time() - start_ts
                    peak_mb = peak.get("peak", 0) / (1024 * 1024)
                    sys.stderr.write(f"[daemon {mode}] response_sent pid={proc.pid} runtime={elapsed:.3f}s peak_rss={peak_mb:.1f}MB\n"); sys.stderr.flush()
                except Exception:
                    pass
            else:
                payload = {"subprocess_error": "No result from subprocess"}
                if request_id is not None:
                    payload["request_id"] = request_id
                stdout.write(json.dumps(payload) + "\n")
                stdout.flush()
                # stderr heartbeat: no result
                try:
                    elapsed = time.time() - start_ts
                    peak_mb = peak.get("peak", 0) / (1024 * 1024)
                    sys.stderr.write(f"[daemon {mode}] no_result pid={proc.pid} runtime={elapsed:.3f}s peak_rss={peak_mb:.1f}MB\n"); sys.stderr.flush()
                except Exception:
                    pass
        except Exception as e:
            resp = {"subprocess_error": f"Failed to read result: {e}"}
            if request_id is not None:
                resp["request_id"] = request_id
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
            # stderr heartbeat: read exception
            try:
                sys.stderr.write(f"[daemon {mode}] read_exception pid={proc.pid} err={e}\n"); sys.stderr.flush()
            except Exception:
                pass
        # Close pipe and reap child to avoid FD/process leaks across many requests
        try:
            parent_ch.close()
        except Exception:
            pass
        try:
            # Child should have already exited; join without waiting
            proc.join(timeout=0)
        except Exception:
            pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["secure", "insecure"], required=True)
    ap.add_argument("--mem", type=int, default=500)
    args = ap.parse_args()
    _run_loop(args.mode, args.mem)


if __name__ == "__main__":
    main()

