"""Benchmark 2: dealer setup time vs. D and n, three-way comparison."""

from __future__ import annotations

import argparse

from lecrv.threshold import deal as baseline_deal
from lecrv.threshold import kelsey_deal, lecrv_deal

from benchmarks.common import time_call, write_csv


def run() -> None:
    configs = [
        (4, 3), (8, 3), (16, 3), (32, 3), (64, 3),
        (16, 2), (16, 5), (16, 8), (16, 12),
    ]
    rows = []
    print(f"{'D':>5} {'n':>3}  {'baseline_ms':>12} "
          f"{'kelsey_ms':>11} {'lecrv_ms':>10}")
    for D, n in configs:
        t_base, _ = time_call(baseline_deal, D, n, repeats=3)
        t_kel, _ = time_call(kelsey_deal, D, n, repeats=3)
        t_lec, _ = time_call(lecrv_deal, D, n, repeats=3)
        rows.append([D, n, t_base, t_kel, t_lec])
        print(f"{D:>5} {n:>3}  {t_base * 1000:>12.2f} "
              f"{t_kel * 1000:>11.2f} {t_lec * 1000:>10.2f}")

    path = write_csv(
        "setup_time",
        ["D", "n", "baseline_seconds", "kelsey_seconds", "lecrv_seconds"],
        rows,
    )
    print(f"\nWrote {path}")


def plot() -> None:
    import csv
    import matplotlib.pyplot as plt
    from benchmarks.common import RESULTS_DIR

    with open(RESULTS_DIR / "setup_time.csv") as f:
        data = list(csv.DictReader(f))

    d_series = [r for r in data if int(r["n"]) == 3]
    n_series = [r for r in data if int(r["D"]) == 16]

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))

    Ds = [int(r["D"]) for r in d_series]
    ax1.plot(Ds, [float(r["baseline_seconds"]) for r in d_series],
             "o-", label="Baseline")
    ax1.plot(Ds, [float(r["kelsey_seconds"]) for r in d_series],
             "D-", label="Kelsey")
    ax1.plot(Ds, [float(r["lecrv_seconds"]) for r in d_series],
             "s-", label="LE-CRV")
    ax1.set_xscale("log", base=2)
    ax1.set_xlabel("Signature budget D (n=3)")
    ax1.set_ylabel("Setup time (s)")
    ax1.set_title("Setup Time vs. D")
    ax1.grid(True, ls=":", alpha=0.5)
    ax1.legend()

    ns = [int(r["n"]) for r in n_series]
    ax2.plot(ns, [float(r["baseline_seconds"]) for r in n_series],
             "o-", label="Baseline")
    ax2.plot(ns, [float(r["kelsey_seconds"]) for r in n_series],
             "D-", label="Kelsey")
    ax2.plot(ns, [float(r["lecrv_seconds"]) for r in n_series],
             "s-", label="LE-CRV")
    ax2.set_xlabel("Party count n (D=16)")
    ax2.set_ylabel("Setup time (s)")
    ax2.set_title("Setup Time vs. n")
    ax2.grid(True, ls=":", alpha=0.5)
    ax2.legend()

    fig.tight_layout()
    out = RESULTS_DIR / "setup_time.png"
    fig.savefig(out, dpi=150)
    print(f"Wrote {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()
    run()
    if args.plot:
        plot()