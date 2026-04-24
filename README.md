# LE-CRV

**Forward-Secure Threshold Lamport Signatures via Lazy-Expanded Puncturable Seeds**
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A post-quantum threshold signature library. Implements and benchmarks three threshold hash-based signature schemes over the same Lamport + Merkle-tree substrate, culminating in **LE-CRV** — a novel construction that adds forward security to the Kelsey-Lang-Lucks 2025 threshold HBS framework via GGM puncturable seed trees.

> ⚠️ **Research prototype.** This is a reference implementation for research and teaching. It has not been audited and is not intended for production deployment.

---

## Deliverables

This repository provides all four assignment deliverables as concrete, verifiable artifacts:

| Deliverable | Where to find it |
|---|---|
| **Completed implementation** | [`src/lecrv/`](src/lecrv/) — 10 modules, ~1,500 lines of Python |
| **Detailed documentation** | This README |
| **Test cases with real data** | [`tests/`](tests/) — ~100 unit and integration tests across 10 test files; see [Testing](#testing) |
| **Automated benchmarking** | [`benchmarks/`](benchmarks/) — 5 scripts, one-command reproduction; see [Benchmarks](#benchmarks) |
| **Demo screenshots** | [`demo-screenshots for experimentation.zip`](demo-screenshots%20for%20experimentation.zip) — captured outputs from every demo script and benchmark run |

---

## Why This Exists

Threshold signature schemes distribute signing authority across `n` parties so no single compromise is catastrophic. Most deployed threshold schemes (ECDSA, Schnorr, BLS) rely on number-theoretic assumptions that **break under quantum computers**.

Hash-based signatures are quantum-resistant, but they're inherently single-signer and stateful. The recent Kelsey-Lang-Lucks 2025 paper showed how to make them threshold — but their scheme has no forward security: if a party is compromised at any time, the attacker learns every share it ever derived, past and future.

**LE-CRV closes that gap.** Each party holds a GGM puncturable seed tree instead of a static PRF key. After signing with KeyID `k`, the tree is *punctured* at `k` so the corresponding share becomes cryptographically unrecoverable — even to the party itself. Everything else — signature format, verifier, aggregator protocol, CRV structure — is preserved exactly.

## Highlights

- 🔐 **Post-quantum secure** — relies only on SHA-256 preimage resistance
- 🛡️ **Forward-secure** — compromise at time `t` cannot reconstruct pre-`t` shares
- 📦 **Standard verifier** — produces byte-identical Lamport signatures
- 🧪 **~100 unit tests** across 10 test modules with real cryptographic data
- 📊 **Reproducible benchmarks** with auto-generated CSVs and plots
- 🐍 **Pure Python** — one dependency (`pycryptodome` for SHA-256)

## Three Schemes, One Codebase

| Scheme | Per-party storage | Forward-secure? | Reference |
|---|---|---|---|
| Naive XOR baseline | `O(D)` shares | ❌ | Pedagogical baseline |
| Kelsey-Lang-Lucks 2025 | `O(1)` PRF key | ❌ | [Kelsey et al., IACR CiC 2025](https://doi.org/10.62056/a6ksudy6b) |
| **LE-CRV (this work)** | `O(log D · p)` post-use | **✅** | *This repository* |

All three produce signatures verifiable by the same routine. The composite public key is a single 32-byte Merkle root regardless of scheme.

## Quick Start

```bash
git clone https://github.com/CodeX-98/le-crv.git
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

Every major component ships with a runnable demo. Screenshots of expected output from each demo are included in [`demo-screenshots for experimentation.zip`](demo-screenshots%20for%20experimentation.zip).

```bash
python examples/lamport_demo.py       # Single-signer Lamport OTS
python examples/stateful_demo.py      # D-time HBS under one Merkle root
python examples/seed_tree_demo.py     # Puncturable seed tree behaviour
python examples/threshold_demo.py     # Naive XOR-baseline threshold
python examples/lecrv_demo.py         # LE-CRV threshold (novel contribution)
```

## Testing

The test suite exercises every module with real cryptographic data — random keys, random messages, randomized Merkle trees, and randomized puncturing orders. Tests live in [`tests/`](tests/) and are run by `pytest`.

### Run the full suite

```bash
pytest -v
```

Expected output (truncated):

```
tests/test_hashing.py::test_hash_length PASSED
tests/test_hashing.py::test_hash_is_deterministic PASSED
tests/test_hashing.py::test_domain_separation PASSED
...
tests/test_lecrv.py::test_forward_security_single_party_compromise PASSED
tests/test_lecrv.py::test_storage_advantage_demonstrable PASSED
===== 100 passed in 4.2s =====
```

### Test inventory

| File | Tests | What it covers |
|---|---|---|
| [`test_hashing.py`](tests/test_hashing.py) | 5 | Domain separation, determinism, output length |
| [`test_lamport.py`](tests/test_lamport.py) | 9+ | OTS keygen, sign/verify roundtrip, rejection of tampering |
| [`test_merkle.py`](tests/test_merkle.py) | 11 | Tree construction, paths for every leaf, forged-path rejection |
| [`test_stateful_lamport.py`](tests/test_stateful_lamport.py) | 13 | D-time HBS, key-reuse rejection, exhaustion handling |
| [`test_seed_tree.py`](tests/test_seed_tree.py) | 15 | GGM expansion, puncturing, forward security property, storage bounds |
| [`test_share_expansion.py`](tests/test_share_expansion.py) | 5 | Leaf-seed → SK-share expansion determinism and independence |
| [`test_xor_utils.py`](tests/test_xor_utils.py) | 4 | Additive sharing reconstruction |
| [`test_threshold.py`](tests/test_threshold.py) | 8 | Naive baseline threshold, subset-forgery rejection |
| [`test_kelsey.py`](tests/test_kelsey.py) | 5 | Kelsey 2025 scheme, forward-security gap documented |
| [`test_lecrv.py`](tests/test_lecrv.py) | 9 | LE-CRV scheme, forward security under party compromise |

### Critical correctness tests

Four tests directly evidence the core security claims:

- `test_subset_of_parties_cannot_forge` (test_threshold.py) — `n-1` parties cannot produce a valid signature
- `test_forward_security_property` (test_seed_tree.py) — post-puncture state does not contain the punctured leaf seed
- `test_forward_security_single_party_compromise` (test_lecrv.py) — compromising any party after signing cannot re-derive the used share
- `test_lecrv_matches_baseline_on_verification` (test_lecrv.py) — LE-CRV signatures verify under the same routine as baseline, confirming wire-format compatibility

### Running tests in CI

The [GitHub Actions workflow](.github/workflows/test.yml) runs the full test suite on Ubuntu, Windows, and macOS across Python 3.10, 3.11, and 3.12 on every push and pull request.

## Benchmarks

The benchmarking pipeline is fully automated. One command produces all CSVs and plots used in the project analysis.

### Run all benchmarks

```bash
python -m benchmarks.run_all
```

Typical runtime: 2–5 minutes on a laptop. Output is written to `benchmarks/results/`.

### Individual benchmarks

Each benchmark can also be run in isolation:

```bash
python -m benchmarks.bench_storage --plot
python -m benchmarks.bench_setup --plot
python -m benchmarks.bench_signing --plot
python -m benchmarks.bench_communication --plot
python -m benchmarks.bench_complexity_comparison --plot
```

### Benchmark inventory

| Script | Measures | Output file (CSV + PNG) |
|---|---|---|
| [`bench_storage.py`](benchmarks/bench_storage.py) | Per-party storage vs. signature budget D across all three schemes | `storage_vs_D` |
| [`bench_setup.py`](benchmarks/bench_setup.py) | Dealer setup time vs. D and n | `setup_time` |
| [`bench_signing.py`](benchmarks/bench_signing.py) | End-to-end signing latency vs. party count n | `signing_latency` |
| [`bench_communication.py`](benchmarks/bench_communication.py) | Bytes exchanged per signature | `communication` |
| [`bench_complexity_comparison.py`](benchmarks/bench_complexity_comparison.py) | Asymptotic comparison across 7 threshold schemes | `scheme_comparison` |

### Visual results from past runs

Captured screenshots of benchmark plots and demo outputs from a local experimentation run are bundled in [`demo-screenshots for experimentation.zip`](demo-screenshots%20for%20experimentation.zip). Extract the archive to view the plots and terminal output without having to rerun the benchmarks yourself.

## Comparison With Related Work

Across seven threshold signature schemes — classical (ECDSA, Schnorr, BLS), lattice-based (Dilithium), and hash-based (naive, Kelsey 2025, LE-CRV):

**LE-CRV is the only scheme in the comparison that is simultaneously (a) post-quantum secure, (b) hash-function-based, and (c) forward-secure at the party level.**

See [`docs/design.md`](docs/design.md) for the full analysis and [`benchmarks/bench_complexity_comparison.py`](benchmarks/bench_complexity_comparison.py) for the generated table.

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
├── tests/                  # ~100 unit and integration tests
├── benchmarks/             # Reproducible benchmark scripts
│   └── results/            # Generated CSVs and PNGs (gitignored)
├── examples/               # Runnable demos (one per component)
├── docs/
│   └── design.md           # Full construction + cost analysis
├── demo-screenshots for experimentation.zip   # Captured demo and benchmark outputs
├── pyproject.toml
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
  url    = {https://github.com/CodeX-98/le-crv},
  note   = {Research prototype and reference implementation}
}
```

## Contributing
Improvements to clarity, benchmarks, and documentation are welcome. Production-oriented optimizations and new dependencies are out of scope until after publication.

## License

MIT.

## Acknowledgments

The construction builds directly on Kelsey, Lang, and Lucks's 2025 threshold HBS paper. The puncturable seed tree is a standard GGM construction, applied here to a new setting. This is the course project for COMP3453 26T1 Applied Cryptography. Thanks.
