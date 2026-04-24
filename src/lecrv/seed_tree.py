"""GGM-style puncturable seed tree.

A seed tree of depth d supports D = 2^d leaves. From a single root seed,
every leaf value can be deterministically derived by walking the tree.
After using leaf i, the tree can be PUNCTURED at i: the party retains just
enough state to derive every other leaf, but leaf i itself becomes
cryptographically unrecoverable (security reduces to SHA-256 preimage
resistance).

Representation after puncturing: a "punctured state" is the list of nodes
on the co-path from the root toward the most-recently-punctured leaf.
More precisely, we store the frontier: the set of subtree roots that
together cover exactly the non-punctured leaves.

For a freshly created tree: the frontier is [root].
After puncturing leaf 0 in a tree of depth 3:
    frontier covers leaves {1}, {2,3}, {4,5,6,7}
    stored as three subtree-root seeds at depths 3, 2, 1 respectively.

This gives O(log D) storage per party regardless of how many leaves have
been punctured so far.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from lecrv.hashing import H, SEC_PARAM, TAG_PRG_LEFT, TAG_PRG_RIGHT


@dataclass(frozen=True)
class SubtreeNode:
    """A node in the frontier: the root seed of some subtree.

    depth:    distance from the tree root (0 = root, d = leaf level)
    index:    horizontal index among nodes at this depth, in [0, 2^depth)
    seed:     the SEC_PARAM-byte seed at this node

    The subtree rooted here covers leaves [index * 2^(d-depth),
    (index+1) * 2^(d-depth)). For leaf-level nodes, it covers exactly one leaf.
    """
    depth: int
    index: int
    seed: bytes


@dataclass
class SeedTree:
    """A puncturable seed tree.

    d:         tree depth; number of leaves is D = 2^d
    frontier:  list of SubtreeNodes that together cover all non-punctured leaves
    punctured: set of leaf indices that have been punctured
    """
    d: int
    frontier: list[SubtreeNode]
    punctured: set[int] = field(default_factory=set)

    @property
    def D(self) -> int:
        return 1 << self.d


def new_tree(d: int, rng=os.urandom) -> SeedTree:
    """Create a fresh seed tree of depth d with a random root seed."""
    if d < 0:
        raise ValueError("depth must be non-negative")
    root = SubtreeNode(depth=0, index=0, seed=rng(SEC_PARAM))
    return SeedTree(d=d, frontier=[root])


def _expand(node_seed: bytes) -> tuple[bytes, bytes]:
    """Deterministically expand a node seed into its two child seeds."""
    return H(TAG_PRG_LEFT, node_seed), H(TAG_PRG_RIGHT, node_seed)


def _leaf_bit_path(leaf_index: int, d: int) -> list[int]:
    """Return the bit path from root to leaf_index as a list of d bits.

    Most significant bit first. bit=0 means "go left", bit=1 means "go right".
    """
    return [(leaf_index >> (d - 1 - i)) & 1 for i in range(d)]


def _descend_to_leaf(root_node: SubtreeNode, leaf_index: int, d: int) -> bytes:
    """Walk down from root_node to leaf_index; return the leaf seed."""
    # How many levels remain below this subtree root.
    levels_below = d - root_node.depth
    if levels_below == 0:
        return root_node.seed

    # Bits of leaf_index local to this subtree.
    # leaf_index is in [root_node.index * 2^levels_below,
    #                   (root_node.index+1) * 2^levels_below).
    local = leaf_index - root_node.index * (1 << levels_below)
    current = root_node.seed
    for bit_pos in range(levels_below):
        shift = levels_below - 1 - bit_pos
        bit = (local >> shift) & 1
        left, right = _expand(current)
        current = left if bit == 0 else right

    return current


def _find_covering_node(tree: SeedTree, leaf_index: int) -> SubtreeNode | None:
    """Return the frontier node whose subtree contains leaf_index, or None.

    Returns None iff leaf_index is currently punctured.
    """
    for node in tree.frontier:
        levels_below = tree.d - node.depth
        span = 1 << levels_below
        low = node.index * span
        high = low + span
        if low <= leaf_index < high:
            return node
    return None


def derive_leaf(tree: SeedTree, leaf_index: int) -> bytes:
    """Return the leaf seed for leaf_index.

    Raises ValueError if the leaf has been punctured.
    """
    if not (0 <= leaf_index < tree.D):
        raise ValueError(f"leaf_index {leaf_index} out of range")
    if leaf_index in tree.punctured:
        raise ValueError(f"leaf {leaf_index} has been punctured")

    covering = _find_covering_node(tree, leaf_index)
    if covering is None:
        # Should not happen if `punctured` is consistent with `frontier`.
        raise RuntimeError(f"no covering node for leaf {leaf_index}; tree corrupt")

    return _descend_to_leaf(covering, leaf_index, tree.d)


def puncture(tree: SeedTree, leaf_index: int) -> None:
    """Puncture `leaf_index` so its seed is no longer recoverable.

    After puncturing, derive_leaf(leaf_index) raises; all other leaves remain
    derivable. Operates in-place on the tree: the frontier is updated and
    the leaf is added to `punctured`.

    Security: once the covering subtree root is expanded into its children
    and only the non-punctured sibling is retained, the path to leaf_index
    is unrecoverable unless SHA-256 is broken (preimage resistance).
    """
    if not (0 <= leaf_index < tree.D):
        raise ValueError(f"leaf_index {leaf_index} out of range")
    if leaf_index in tree.punctured:
        raise ValueError(f"leaf {leaf_index} already punctured")

    covering = _find_covering_node(tree, leaf_index)
    if covering is None:
        raise RuntimeError(f"no covering node for leaf {leaf_index}; tree corrupt")

    # Remove the covering node from the frontier.
    tree.frontier.remove(covering)

    # Walk from covering down toward leaf_index, at each step keeping the
    # sibling subtree as a new frontier node and descending into the side
    # that contains leaf_index. Stop when we reach the leaf level; at that
    # point, the leaf itself is the thing being punctured, so we do NOT
    # add it to the frontier.
    current = covering
    while current.depth < tree.d:
        levels_below = tree.d - current.depth
        local = leaf_index - current.index * (1 << levels_below)
        shift = levels_below - 1
        bit = (local >> shift) & 1

        left_seed, right_seed = _expand(current.seed)
        child_depth = current.depth + 1
        left_child = SubtreeNode(
            depth=child_depth,
            index=current.index * 2,
            seed=left_seed,
        )
        right_child = SubtreeNode(
            depth=child_depth,
            index=current.index * 2 + 1,
            seed=right_seed,
        )

        if bit == 0:
            # Going left toward the punctured leaf; keep the right sibling.
            tree.frontier.append(right_child)
            current = left_child
        else:
            tree.frontier.append(left_child)
            current = right_child

    # `current` is now the leaf node for leaf_index itself.
    # We deliberately discard `current.seed` here — it never enters the frontier.
    tree.punctured.add(leaf_index)

    # Keep frontier sorted by (depth, index) for deterministic serialization.
    tree.frontier.sort(key=lambda n: (n.depth, n.index))


def storage_bytes(tree: SeedTree) -> int:
    """Current storage cost of the tree in bytes.

    Each SubtreeNode contributes SEC_PARAM bytes of seed. We ignore the
    constant overhead of depth/index integers, which are log D bits each.
    """
    return len(tree.frontier) * SEC_PARAM