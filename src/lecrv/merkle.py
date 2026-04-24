"""Merkle tree over Lamport public keys.

We use a standard binary Merkle tree on D = 2^d leaves, where each leaf is a
32-byte commitment to one Lamport public key. The root of this tree is the
composite public key that a verifier uses to validate any of the D one-time
signatures.

Storage is a 1-indexed array of length 2D:
  - index 1 is the root
  - index i has children at 2i and 2i+1
  - leaves occupy indices D through 2D-1

A PATH from leaf KeyID up to the root is the list of sibling hashes encountered
on the way up, plus the KeyID itself so the verifier knows which leaf is being
proven.
"""

from __future__ import annotations

from dataclasses import dataclass

from lecrv.hashing import H, HASH_LEN, TAG_MERKLE_LEAF, TAG_MERKLE_NODE


@dataclass(frozen=True)
class MerklePath:
    """A Merkle authentication path.

    key_id:   index of the leaf being proven, in {0, ..., D-1}
    siblings: list of sibling hashes from leaf-level up to just below the root.
              Length equals the tree depth d = log2(D).
    """
    key_id: int
    siblings: list[bytes]


def _check_power_of_two(D: int) -> None:
    if D < 1 or (D & (D - 1)) != 0:
        raise ValueError(f"D must be a power of two, got {D}")


def build_tree(leaves: list[bytes]) -> list[bytes]:
    """Build a Merkle tree over the given leaf digests.

    Each leaf is expected to already be a 32-byte digest (use lamport.pk_digest
    on a Lamport public key to produce one). We additionally tag leaves with
    TAG_MERKLE_LEAF and internal nodes with TAG_MERKLE_NODE so the two can
    never be confused by an attacker.

    Returns the full tree array. Tree[1] is the root.
    """
    D = len(leaves)
    _check_power_of_two(D)
    for leaf in leaves:
        if len(leaf) != HASH_LEN:
            raise ValueError("every leaf must be HASH_LEN bytes")

    tree: list[bytes] = [b""] * (2 * D)

    # Place tagged leaves at the bottom.
    for i in range(D):
        tree[D + i] = H(TAG_MERKLE_LEAF, leaves[i])

    # Build up internal nodes.
    for i in range(D - 1, 0, -1):
        tree[i] = H(TAG_MERKLE_NODE, tree[2 * i], tree[2 * i + 1])

    return tree


def root(tree: list[bytes]) -> bytes:
    """Return the root (index 1) of a Merkle tree."""
    return tree[1]


def make_path(tree: list[bytes], key_id: int) -> MerklePath:
    """Build an authentication path for the leaf at key_id.

    Walks from the leaf up to the root, recording the sibling at each level.
    """
    D = len(tree) // 2
    _check_power_of_two(D)
    if not (0 <= key_id < D):
        raise ValueError(f"key_id {key_id} out of range for D={D}")

    siblings: list[bytes] = []
    i = key_id + D  # index of the leaf in the array
    while i > 1:
        sibling = tree[i ^ 1]  # XOR with 1 flips to the sibling
        siblings.append(sibling)
        i //= 2

    return MerklePath(key_id=key_id, siblings=siblings)


def verify_path(path: MerklePath, leaf: bytes, expected_root: bytes) -> bool:
    """Verify that leaf, with the given path, reconstructs expected_root.

    Returns True iff the leaf sits at position path.key_id in a tree whose
    root equals expected_root.
    """
    if len(leaf) != HASH_LEN:
        return False

    # Infer D from the path length.
    d = len(path.siblings)
    D = 1 << d
    if not (0 <= path.key_id < D):
        return False

    # Rebuild from the leaf up.
    current = H(TAG_MERKLE_LEAF, leaf)
    i = path.key_id + D
    for sibling in path.siblings:
        if i % 2 == 0:
            # current is the left child, sibling is right
            current = H(TAG_MERKLE_NODE, current, sibling)
        else:
            current = H(TAG_MERKLE_NODE, sibling, current)
        i //= 2

    return current == expected_root