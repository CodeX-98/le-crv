"""Run every benchmark and produce every plot.

Usage from project root:

    python -m benchmarks.run_all
"""

from __future__ import annotations

from benchmarks import (
    bench_communication,
    bench_complexity_comparison,
    bench_setup,
    bench_signing,
    bench_storage,
)


def main() -> None:
    for name, mod in [
        ("Storage vs. D", bench_storage),
        ("Setup time", bench_setup),
        ("Signing latency", bench_signing),
        ("Communication", bench_communication),
        ("Complexity comparison", bench_complexity_comparison),
    ]:
        print(f"\n{'=' * 70}\n  {name}\n{'=' * 70}")
        mod.run()
        mod.plot()


if __name__ == "__main__":
    main()