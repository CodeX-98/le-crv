"""Benchmark 1: per-party storage vs. signature budget D.

Three-way comparison:
  - Naive baseline:  D pre-computed XOR shares per party -> O(D)
  - Kelsey-Lang-Lucks 2025:   one PRF key per party -> O(1)
  - LE-CRV (this work):       seed tree, O(log D * p) after p punctures

The headline result: LE-CRV matches Kelsey's low storage at initial state,
and trades a small storage increase (growing logarithmically with use) for
forward security that Kelsey lacks.
"""

from __future__ import annotations

import argparse

from lecrv.lamport import NUM_BITS
from lecrv.seed_tree import storage_bytes
from lecrv.threshold import (
    KelseyAggregator,
    KelseyParty,
    LecrvAggregator,
    LecrvParty,
    kelsey_deal,
    lecrv_deal,
)

from benchmarks.common import write_csv

BASELINE_BYTES_PER_KEYID = 2 * NUM_BITS * 32


def baseline_party_storage(D: int) -> int:
    return D * BASELINE_BYTES_PER_KEYID


def kelsey_party_storage(D: int) -> int:
    return 32  # single PRF key, independent of D


def lecrv_storage_after_sequential_use(D: int, n: int, k: int) -> int:
    public, bundles = lecrv_deal(D=D, n=n)
    parties = [LecrvParty(bundle=b) for b in bundles]
    agg = LecrvAggregator(public=public)
    for key_id in range(k):
        agg.sign(parties, key_id=key_id, msg=b"x")
    return storage_bytes(parties[0].tree)


def run() -> None:
    Ds = [2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]
    rows = []
    print(f"{'D':>6} {'baseline':>12} {'kelsey':>10} "
          f"{'lecrv_init':>12} {'lecrv_half':>12}")
    for D in Ds:
        baseline = baseline_party_storage(D)
        kelsey = kelsey_party_storage(D)
        lecrv_init = 32
        lecrv_half = lecrv_storage_after_sequential_use(D, n=3, k=D // 2)
        rows.append([D, baseline, kelsey, lecrv_init, lecrv_half])
        print(f"{D:>6} {baseline:>12} {kelsey:>10} "
              f"{lecrv_init:>12} {lecrv_half:>12}")

    path = write_csv(
        "storage_vs_D",
        ["D", "baseline_bytes", "kelsey_bytes",
         "lecrv_initial_bytes", "lecrv_half_used_bytes"],
        rows,
    )
    print(f"\nWrote {path}")


def plot() -> None:
    import csv
    import matplotlib.pyplot as plt
    from benchmarks.common import RESULTS_DIR

    with open(RESULTS_DIR / "storage_vs_D.csv") as f:
        data = list(csv.DictReader(f))

    Ds = [int(r["D"]) for r in data]
    baseline = [int(r["baseline_bytes"]) for r in data]
    kelsey = [int(r["kelsey_bytes"]) for r in data]
    lecrv_init = [int(r["lecrv_initial_bytes"]) for r in data]
    lecrv_half = [int(r["lecrv_half_used_bytes"]) for r in data]

    fig, ax = plt.subplots(figsize=(9, 5.5))
    ax.plot(Ds, baseline, "o-", label="Naive baseline (Step 4)")
    ax.plot(Ds, kelsey, "D-", label="Kelsey-Lang-Lucks 2025")
    ax.plot(Ds, lecrv_init, "^--", label="LE-CRV (initial state)")
    ax.plot(Ds, lecrv_half, "s-", label="LE-CRV (after D/2 signatures)")
    ax.set_xscale("log", base=2)
    ax.set_yscale("log", base=2)
    ax.set_xlabel("Signature budget D")
    ax.set_ylabel("Per-party storage (bytes, log scale)")
    ax.set_title("Per-Party Storage: Three-Way Comparison")
    ax.grid(True, which="both", ls=":", alpha=0.5)
    ax.legend()
    fig.tight_layout()

    out = RESULTS_DIR / "storage_vs_D.png"
    fig.savefig(out, dpi=150)
    print(f"Wrote {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()
    run()
    if args.plot:
        plot()