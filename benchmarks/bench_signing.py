"""Benchmark 3: per-signature latency vs. party count n, three-way."""

from __future__ import annotations

import argparse

from lecrv.threshold import (
    Aggregator,
    KelseyAggregator,
    KelseyParty,
    LecrvAggregator,
    LecrvParty,
    Party,
)
from lecrv.threshold import deal as baseline_deal
from lecrv.threshold import kelsey_deal, lecrv_deal

from benchmarks.common import time_call, write_csv


D = 16
MSG = b"benchmark message of moderate length for a realistic signing call"


def measure_baseline(n: int) -> float:
    def _one():
        pub, bundles = baseline_deal(D=D, n=n)
        parties = [Party(bundle=b) for b in bundles]
        agg = Aggregator(public=pub)
        return agg.sign(parties, key_id=0, msg=MSG)
    t, _ = time_call(_one, repeats=5)
    return t


def measure_kelsey(n: int) -> float:
    def _one():
        pub, bundles = kelsey_deal(D=D, n=n)
        parties = [KelseyParty(bundle=b) for b in bundles]
        agg = KelseyAggregator(public=pub)
        return agg.sign(parties, key_id=0, msg=MSG)
    t, _ = time_call(_one, repeats=5)
    return t


def measure_lecrv(n: int) -> float:
    def _one():
        pub, bundles = lecrv_deal(D=D, n=n)
        parties = [LecrvParty(bundle=b) for b in bundles]
        agg = LecrvAggregator(public=pub)
        return agg.sign(parties, key_id=0, msg=MSG)
    t, _ = time_call(_one, repeats=5)
    return t


def run() -> None:
    ns = [2, 3, 4, 5, 8, 12, 16]
    rows = []
    print(f"{'n':>3}  {'baseline_ms':>12} {'kelsey_ms':>11} {'lecrv_ms':>10}")
    for n in ns:
        t_b = measure_baseline(n)
        t_k = measure_kelsey(n)
        t_l = measure_lecrv(n)
        rows.append([n, t_b, t_k, t_l])
        print(f"{n:>3}  {t_b * 1000:>12.2f} {t_k * 1000:>11.2f} {t_l * 1000:>10.2f}")

    path = write_csv(
        "signing_latency",
        ["n", "baseline_seconds", "kelsey_seconds", "lecrv_seconds"],
        rows,
    )
    print(f"\nWrote {path}")


def plot() -> None:
    import csv
    import matplotlib.pyplot as plt
    from benchmarks.common import RESULTS_DIR

    with open(RESULTS_DIR / "signing_latency.csv") as f:
        data = list(csv.DictReader(f))

    ns = [int(r["n"]) for r in data]
    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.plot(ns, [float(r["baseline_seconds"]) * 1000 for r in data],
            "o-", label="Baseline")
    ax.plot(ns, [float(r["kelsey_seconds"]) * 1000 for r in data],
            "D-", label="Kelsey")
    ax.plot(ns, [float(r["lecrv_seconds"]) * 1000 for r in data],
            "s-", label="LE-CRV")
    ax.set_xlabel("Party count n")
    ax.set_ylabel("Per-signature time (ms, includes setup)")
    ax.set_title(f"Signing Latency vs. n (D={D})")
    ax.grid(True, ls=":", alpha=0.5)
    ax.legend()
    fig.tight_layout()

    out = RESULTS_DIR / "signing_latency.png"
    fig.savefig(out, dpi=150)
    print(f"Wrote {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()
    run()
    if args.plot:
        plot()