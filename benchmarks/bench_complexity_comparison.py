"""Benchmark 5: asymptotic complexity comparison across threshold signature
schemes.

This directly answers the assignment's "complexity analysis / comparison"
requirement, placing LE-CRV against both classical threshold signatures and
published post-quantum threshold constructions (including the base paper,
Kelsey-Lang-Lucks 2025).

Key finding: LE-CRV is the only scheme in the table that is simultaneously
(a) post-quantum secure, (b) hash-function-based, and (c) forward-secure at
the party level.
"""

from __future__ import annotations

import argparse

from benchmarks.common import write_csv


ROWS = [
    [
        "Threshold ECDSA (GG18)",
        "No",
        "O(1)",
        "N/A (no aggregator)",
        "O(n^2) DKG",
        "~64",
        "8+",
        "No",
        "Yes (ECDSA)",
    ],
    [
        "Threshold Schnorr (FROST)",
        "No",
        "O(1)",
        "N/A",
        "O(n)",
        "~64",
        "2",
        "No",
        "Yes (Schnorr)",
    ],
    [
        "Threshold BLS",
        "No",
        "O(1)",
        "N/A",
        "O(n)",
        "~48",
        "1",
        "No",
        "Yes (BLS)",
    ],
    [
        "Threshold Dilithium (lattice)",
        "Yes (lattice)",
        "O(1)",
        "N/A",
        "O(n)",
        "~2420",
        "3+",
        "No",
        "Partial",
    ],
    [
        "Naive XOR baseline (Step 4)",
        "Yes (hash)",
        "O(D) shares",
        "0",
        "O(D)",
        "~8200 (Lamport)",
        "2",
        "No",
        "Yes (Lamport/HBS)",
    ],
    [
        "Kelsey-Lang-Lucks 2025",
        "Yes (hash)",
        "O(1) PRF key",
        "O(D) CRV (GiB-scale)",
        "O(D)",
        "~8200 (Lamport)",
        "2",
        "No",
        "Yes (Lamport/HBS)",
    ],
    [
        "LE-CRV (this work)",
        "Yes (hash)",
        "O(log D * p) post-use",
        "O(D) CRV",
        "O(D)",
        "~8200 (Lamport)",
        "2",
        "Yes (puncturing)",
        "Yes (Lamport/HBS)",
    ],
]

HEADERS = [
    "Scheme",
    "Post-quantum",
    "Per-party storage",
    "Aggregator storage",
    "Dealer setup",
    "Sig size (B)",
    "Rounds",
    "Forward-secure",
    "Std. verifier",
]


def _render_table(rows: list[list[str]]) -> str:
    widths = [max(len(str(r[i])) for r in ([HEADERS] + rows))
              for i in range(len(HEADERS))]
    sep = "+".join("-" * (w + 2) for w in widths)
    sep = f"+{sep}+"

    def row(cells):
        return "| " + " | ".join(
            str(c).ljust(widths[i]) for i, c in enumerate(cells)
        ) + " |"

    lines = [sep, row(HEADERS), sep]
    for r in rows:
        lines.append(row(r))
    lines.append(sep)
    return "\n".join(lines)


def run() -> None:
    print("Threshold Signature Scheme Comparison\n")
    print(_render_table(ROWS))
    print()
    print("Notes:")
    print("  - D = signature budget per composite key (stateful HBS only)")
    print("  - n = number of parties / trustees")
    print("  - p = number of signatures already produced (LE-CRV only)")
    print("  - HBS signature sizes are Lamport w/ SHA-256; Winternitz is smaller")
    print("  - 'Forward-secure' = compromise of party at time t does NOT expose")
    print("    shares used before t, without requiring re-dealing")
    print("  - Kelsey-Lang-Lucks 2025 achieves constant per-party storage but")
    print("    lacks forward security. LE-CRV trades a small storage increase")
    print("    (growing with p) for structural forward security.")
    print("  - ECDSA/Schnorr/BLS/Dilithium sizes are approximate")
    print("  - Dilithium size is NIST FIPS 204 Dilithium2")

    path = write_csv("scheme_comparison", HEADERS, ROWS)
    print(f"\nWrote {path}")


def plot() -> None:
    import matplotlib.pyplot as plt
    from benchmarks.common import RESULTS_DIR

    fig, ax = plt.subplots(figsize=(15, 4.6))
    ax.axis("off")

    table = ax.table(
        cellText=ROWS,
        colLabels=HEADERS,
        loc="center",
        cellLoc="left",
        colLoc="left",
    )
    table.auto_set_font_size(False)
    table.set_fontsize(8.5)
    table.scale(1, 1.7)

    # Highlight our scheme in green.
    ncols = len(HEADERS)
    for j in range(ncols):
        cell = table[len(ROWS), j]
        cell.set_facecolor("#e6f4ea")
    # Highlight the Kelsey row in light blue for reference.
    for j in range(ncols):
        cell = table[len(ROWS) - 1, j]
        cell.set_facecolor("#e3f2fd")

    ax.set_title("Comparison of Threshold Signature Schemes", pad=20)
    fig.tight_layout()

    out = RESULTS_DIR / "scheme_comparison.png"
    fig.savefig(out, dpi=150, bbox_inches="tight")
    print(f"Wrote {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--plot", action="store_true")
    args = parser.parse_args()
    run()
    if args.plot:
        plot()