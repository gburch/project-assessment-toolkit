"""Optional phase and elapsed-time reporting for a long local command."""

from __future__ import annotations

import sys
import threading
import time
from contextlib import contextmanager

_sink = None


def report(phase):
    """Announce a phase; no adapter except the CLI opts in, so MCP and tests stay silent."""
    if _sink is not None:
        _sink(phase)


def _clock(seconds):
    minutes, seconds = divmod(int(seconds), 60)
    return f"{minutes}m{seconds:02d}s"


@contextmanager
def stderr_progress(*, stream=None, heartbeat_seconds=30.0):
    """Print each phase to stderr, then repeat the current one so slow is not read as stuck."""
    global _sink
    stream = stream or sys.stderr
    started = time.monotonic()
    state = {"phase": "starting"}
    finished = threading.Event()
    lock = threading.Lock()

    def write(text):
        with lock:
            print(f"pat: [{_clock(time.monotonic() - started)}] {text}", file=stream, flush=True)

    def sink(phase):
        state["phase"] = phase
        write(phase)

    def beat():
        while not finished.wait(heartbeat_seconds):
            write(f"{state['phase']} (still running)")

    worker = threading.Thread(target=beat, daemon=True)
    previous, _sink = _sink, sink
    worker.start()
    try:
        yield
        write("finished")
    finally:
        finished.set()
        worker.join()
        _sink = previous
