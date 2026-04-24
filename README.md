# LE-CRV

**Forward-Secure Threshold Lamport Signatures via Lazy-Expanded Puncturable Seeds**
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A post-quantum threshold signature library. Implements and benchmarks three threshold hash-based signature schemes over the same Lamport + Merkle-tree substrate, culminating in **LE-CRV** — a novel construction that adds forward security to the Kelsey-Lang-Lucks 2025 threshold HBS framework via GGM puncturable seed trees.

> ⚠️ **Research prototype.** This is a reference implementation for research and teaching. It has not been audited and is not intended for production deployment.

---

## Why This Exists

Threshold signature schemes distribute signing authority across `n` parties so no single compromise is catastrophic. Most deployed threshold schemes (ECDSA, Schnorr, BLS) rely on number-theoretic assumptions that **break under quantum computers**.

Hash-based signatures are quantum-resistant, but they're inherently single-signer and stateful. The recent Kelsey-Lang-Lucks 2025 paper showed how to make them threshold — but their scheme has no forward security: if a party is compromised at any time, the attacker learns every share it ever derived, past and future.

**LE-CRV closes that gap.** Each party holds a GGM puncturable seed tree instead of a static PRF key. After signing with KeyID `k`, the tree is *punctured* at `k` so the corresponding share becomes cryptographically unrecoverable — even to the party itself. Everything else — signature format, verifier, aggregator protocol, CRV structure — is preserved exactly.

## Highlights

- 🔐 **Post-quantum secure** — relies only on SHA-256 preimage resistance
- 🛡️ **Forward-secure** — compromise at time `t` cannot reconstruct pre-`t` shares
- 📦 **Standard verifier** — produces byte-identical Lamport signatures
- 🧪 **~100 unit tests** across 10 test modules
- 📊 **Reproducible benchmarks** with auto-generated plots
- 🐍 **Pure Python** — one dependency (`pycryptodome` for SHA-256)

## Three Schemes, One Codebase

| Scheme | Per-party storage | Forward-secure? | Reference |
|---|---|---|---|
| Naive XOR baseline | `O(D)` shares | ❌ | pedagogical baseline |
| Kelsey-Lang-Lucks 2025 | `O(1)` PRF key | ❌ | [Kelsey et al., IACR CiC 2025](https://doi.org/10.62056/a6ksudy6b) |
| **LE-CRV (this work)** | `O(log D · p)` post-use | **✅** | *This repository* |

All three produce signatures verifiable by the same routine. The composite public key is a single 32-byte Merkle root regardless of scheme.

## Quick Start

```bash
git clone https://github.com/YOUR_USERNAME/le-crv.git
cd le-crv
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

pip install -e ".[dev]"
pytest -v
```

Then a three-line signing example:

```python
from lecrv.stateful_lamport import verify_with_pk
from lecrv.threshold import LecrvAggregator, LecrvParty, lecrv_deal

# Trusted setup: D=8 one-time keys, n=3 parties.
public, bundles = lecrv_deal(D=8, n=3)
parties = [LecrvParty(bundle=b) for b in bundles]
agg = LecrvAggregator(public=public)

# Parties jointly sign.
sig = agg.sign(parties, key_id=0, msg=b"hello post-quantum world")

# Verify with the same routine any stateful-HBS verifier uses.
pk = public.one_time_pks[sig.key_id]
assert verify_with_pk(public.public_root, b"hello post-quantum world", sig, pk)
print("verified ✓")
```

## Demos

Every major component ships with a runnable demo:

```bash
python examples/lamport_demo.py       # Single-signer Lamport OTS
python examples/stateful_demo.py      # D-time HBS under one Merkle root
python examples/seed_tree_demo.py     # Puncturable seed tree behaviour
python examples/threshold_demo.py     # Naive XOR-baseline threshold
python examples/lecrv_demo.py         # LE-CRV threshold (novel contribution)
```

## Benchmarks

Regenerate all figures and CSVs:

```bash
python -m benchmarks.run_all
```

Output lands in `benchmarks/results/`:

| File | What it shows |
|---|---|
| `storage_vs_D.{csv,png}` | Per-party storage across all three schemes vs. signature budget D |
| `setup_time.{csv,png}` | Dealer setup time vs. D and n |
| `signing_latency.{csv,png}` | End-to-end signing time vs. party count n |
| `communication.{csv,png}` | Bytes exchanged per signature |
| `scheme_comparison.{csv,png}` | Complexity comparison across 7 threshold schemes |

Typical runtime: 2–5 minutes on a laptop.

## Comparison With Related Work

Across seven threshold signature schemes — classical (ECDSA, Schnorr, BLS), lattice-based (Dilithium), and hash-based (naive, Kelsey 2025, LE-CRV):

**LE-CRV is the only scheme in the comparison that is simultaneously (a) post-quantum secure, (b) hash-function-based, and (c) forward-secure at the party level.**

See  [`benchmarks/bench_complexity_comparison.py`](benchmarks/bench_complexity_comparison.py) for the generated table.

## How LE-CRV Works

Each party's state is a GGM binary tree of depth `d = log₂(D)`:

- The party's initial state is one 32-byte root seed.
- Leaf `k` corresponds to KeyID `k` and expands into a full Lamport-SK-shaped share.
- Each internal node expands to children via domain-separated SHA-256:
  `left = H(TAG_L, node)`, `right = H(TAG_R, node)`.
- After signing with KeyID `k`, the party **punctures** the tree: the root-to-leaf path for `k` is expanded, only the sibling subtree roots are kept, and the leaf itself is discarded.
- Re-deriving the leaf for `k` post-puncture requires a SHA-256 preimage — the same assumption that underlies the signature scheme itself.

The dealer publishes a correction table (the CRV) so that `XOR_p(share_p) XOR correction = true_sk`. Because the correction is public and the verifier only sees the final combined signature, LE-CRV is a drop-in for any system running Kelsey et al.'s construction.

## Project Layout

```
le-crv/
├── src/lecrv/              # Library source
│   ├── hashing.py          # Domain-separated SHA-256
│   ├── lamport.py          # Lamport one-time signatures
│   ├── merkle.py           # Merkle tree over leaf digests
│   ├── stateful_lamport.py # D-time HBS: Lamport + Merkle
│   ├── seed_tree.py        # GGM puncturable seed tree (novel)
│   ├── share_expansion.py  # Leaf-seed → SK-share expansion
│   ├── xor_utils.py        # XOR helpers for additive sharing
│   └── threshold/
│       ├── dealer.py  party.py  aggregator.py              # Naive baseline
│       ├── kelsey_dealer.py  kelsey_party.py  kelsey_aggregator.py
│       └── lecrv_dealer.py   lecrv_party.py   lecrv_aggregator.py
├── tests/                  # ~100 unit tests
├── benchmarks/             # Reproducible benchmark scripts
│   └── results/            # Generated CSVs and PNGs (gitignored)
├── examples/               # Runnable demos (one per component)
├── docs/
│   └── design.md           # Full construction + cost analysis
├── pyproject.toml
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md
```

## Limitations

Honest about what this is and isn't:

- **Dealer must be trusted.** Removing this assumption (distributed key generation for stateful HBS) is open work.
- **Aggregator CRV size is unchanged from Kelsey et al.** LE-CRV optimizes the *party's* state, not the aggregator's.
- **Lamport, not Winternitz.** Signatures are ~8.2 KiB. A Winternitz variant would preserve all scheme properties with much smaller signatures.
- **Backward security is NOT provided.** An attacker who compromises a party's post-puncture state can derive future shares until the next puncture. Backward security requires orthogonal techniques (key-insulated signatures, proactive refresh).

## Related Work

Built on the shoulders of:

- **Kelsey, Lang, Lucks.** *Turning Hash-Based Signatures into Distributed Signatures and Threshold Signatures.* IACR Communications in Cryptology, 2025. [[paper]](https://doi.org/10.62056/a6ksudy6b)
- **Lamport.** *Constructing Digital Signatures from a One Way Function.* SRI Technical Report, 1979.
- **Merkle.** *A Certified Digital Signature.* CRYPTO '89.
- **Goldreich, Goldwasser, Micali.** *How to Construct Random Functions.* J. ACM, 1986. (The GGM tree construction.)
- **Sahai, Waters.** *How to Use Indistinguishability Obfuscation: Deniable Encryption, and More.* STOC 2014. (Puncturable PRFs as a primitive.)

## Citing

If you use this library in research, please cite:

```bibtex
@misc{lecrv2026,
  author = {Nishant Jha},
  title  = {{LE-CRV}: Forward-Secure Threshold Lamport Signatures via Lazy-Expanded Puncturable Seeds},
  year   = {2026},
  url    = {https://github.com/YOUR_USERNAME/le-crv},
  note   = {Research prototype and reference implementation}
}
```

## Contributing
Improvements to clarity, benchmarks, and documentation are welcome. Production-oriented optimizations and new dependencies are out of scope until after publication.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

The construction builds directly on Kelsey, Lang, and Lucks's 2025 threshold HBS paper. The puncturable seed tree is a standard GGM construction, applied here to a new setting. This is the term project for the course COMP3453 26T1 (UNSW)
