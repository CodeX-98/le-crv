"""Shared helpers for benchmark scripts.

Every benchmark script writes a CSV under benchmarks/results/ and, when
invoked with --plot, generates a matching PNG.
"""

from __future__ import annotations

import csv
import os
import time
from pathlib import Path


RESULTS_DIR = Path(__file__).parent / "results"
RESULTS_DIR.mkdir(exist_ok=True)


def write_csv(name: str, headers: list[str], rows: list[list]) -> Path:
    """Write rows to benchmarks/results/<name>.csv and return the path."""
    path = RESULTS_DIR / f"{name}.csv"
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerows(rows)
    return path


def time_call(fn, *args, repeats: int = 3, **kwargs) -> tuple[float, object]:
    """Run fn(*args, **kwargs) `repeats` times; return (min_seconds, last_result).

    We report the minimum across repeats, which is the standard practice for
    microbenchmarks: it filters out noise from GC, interrupts, etc., and
    approximates the best-case execution time on the machine.
    """
    best = float("inf")
    result = None
    for _ in range(repeats):
        t0 = time.perf_counter()
        result = fn(*args, **kwargs)
        dt = time.perf_counter() - t0
        if dt < best:
            best = dt
    return best, result


def human_bytes(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TiB"