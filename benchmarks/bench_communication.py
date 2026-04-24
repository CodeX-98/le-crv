"""Benchmark 4: communication cost per signature.

All three schemes (baseline, Kelsey, LE-CRV) exchange the same messages:
aggregator broadcasts (key_id, msg); each party returns its NUM_BITS*32-byte
signature share. Communication is scheme-independent; LE-CRV adds zero wire
overhead. This benchmark documents that fact for the paper.
"""

from __future__ import annotations

import argparse

from lecrv.lamport import NUM_BITS
from benchmarks.common import write_csv


MSG_LEN = 64
KEY_ID_LEN = 4


def bytes_per_signature(n: int) -> dict:
    share_size = NUM_BITS * 32
    req_per_party = KEY_ID_LEN + MSG_LEN
    resp_per_party = share_size
    return {
        "n": n,
        "request_per_party_B": req_per_party,
        "response_per_party_B": resp_per_party,
        "total_out_B": n * req_per_party,
        "total_in_B": n * resp_per_party,
        "total_B": n * (req_per_party + resp_per_party),
    }


def run() -> None:
    ns = [2, 3, 4, 5, 8, 12, 16, 24]
    rows = []
    print("All three schemes share identical per-signature communication.\n")
    for n in ns:
        info = bytes_per_signature(n)
        rows.append([
            info["n"], info["request_per_party_B"], info["response_per_party_B"],
            info["total_out_B"], info["total_in_B"], info["total_B"],
        ])
        print(f"n={info['n']:2d}  out={info['total_out_B']:>6d}B  "
              f"in={info['total_in_B']:>7d}B  total={info['total_B']:>7d}B")

    path = write_csv(
        "communication",
        ["n", "request_per_party_B", "response_per_party_B",
         "total_out_B", "total_in_B", "total_B"],
        rows,
    )
    print(f"\nWrote {path}")


def plot() -> None:
    import csv
    import matplotlib.pyplot as plt
    from benchmarks.common import RESULTS_DIR

    with open(RESULTS_DIR / "communication.csv") as f:
        data = list(csv.DictReader(f))

    ns = [int(r["n"]) for r in data]
    totals = [int(r["total_B"]) for r in data]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.plot(ns, totals, "o-",
            label="All three schemes (identical)")
    ax.set_xlabel("Party count n")
    ax.set_ylabel("Total bytes exchanged per signature")
    ax.set_title("Communication Cost per Signature")
    ax.grid(True, ls=":", alpha=0.5)
    ax.legend()
    fig.tight_layout()

    out = RESULTS_DIR / "communication.png"
    fig.savefig(out, dpi=150)
    print(f"Wrote {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()
    run()
    if args.plot:
        plot()