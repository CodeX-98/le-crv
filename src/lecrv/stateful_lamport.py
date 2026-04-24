"""Stateful hash-based signatures: D Lamport keys under one Merkle root.

This module composes the single-signer Lamport scheme with a Merkle tree so
that one 32-byte public key (the Merkle root) suffices to verify up to D
signatures. The signer maintains state — specifically, a set of used KeyIDs —
and refuses to sign twice with the same one-time key.

Reusing a Lamport key is catastrophic: an adversary who sees two signatures
under the same key can typically forge arbitrary messages. The state check
here is the primary defense against that failure mode in the single-signer
setting. The threshold layer built on top (Step 4+) replaces this single
point of failure with a distributed one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from lecrv import lamport, merkle
from lecrv.lamport import LamportKeypair
from lecrv.merkle import MerklePath


@dataclass
class CompositeKeypair:
    """Output of keygen for the stateful scheme.

    public_root: the Merkle root that verifiers will use (32 bytes).
    keypairs:    the D underlying Lamport keypairs, indexed by KeyID.
    tree:        the fully built Merkle tree array, kept for fast path
                 generation during signing.
    used:        the set of KeyIDs already consumed. Mutated on each sign().
    """
    public_root: bytes
    keypairs: list[LamportKeypair]
    tree: list[bytes]
    used: set[int] = field(default_factory=set)


@dataclass(frozen=True)
class Signature:
    """A stateful Lamport signature.

    key_id:       which one-time key was used, in {0, ..., D-1}
    lamport_sig:  the NUM_BITS-slot Lamport signature on the message
    path:         Merkle authentication path proving the corresponding PK
                  sits under the composite root
    """
    key_id: int
    lamport_sig: list[bytes]
    path: MerklePath


class KeyReuseError(Exception):
    """Raised when the signer is asked to reuse a KeyID. This is a bug, not
    a transient error — recovery from a detected reuse attempt requires
    human review of the state store."""


class KeyExhaustedError(Exception):
    """Raised when every KeyID has already been used."""


def keygen(D: int) -> CompositeKeypair:
    """Generate a composite keypair that can sign up to D messages."""
    if D < 1 or (D & (D - 1)) != 0:
        raise ValueError(f"D must be a power of two, got {D}")

    keypairs = [lamport.keygen() for _ in range(D)]
    leaves = [lamport.pk_digest(kp.pk) for kp in keypairs]
    tree = merkle.build_tree(leaves)

    return CompositeKeypair(
        public_root=merkle.root(tree),
        keypairs=keypairs,
        tree=tree,
        used=set(),
    )


def next_unused_key_id(ck: CompositeKeypair) -> int:
    """Return the lowest KeyID that has not yet been used.

    Raises KeyExhaustedError if all KeyIDs are spent.
    """
    D = len(ck.keypairs)
    for i in range(D):
        if i not in ck.used:
            return i
    raise KeyExhaustedError("composite key has no unused one-time keys remaining")


def sign(ck: CompositeKeypair, msg: bytes, key_id: int | None = None) -> Signature:
    """Produce a stateful signature on msg.

    If key_id is None (default), uses the lowest-numbered unused KeyID.
    If key_id is specified, uses that KeyID — and refuses if it has been used.

    Mutates ck.used.
    """
    if key_id is None:
        key_id = next_unused_key_id(ck)

    if key_id in ck.used:
        raise KeyReuseError(f"KeyID {key_id} has already been used")
    if not (0 <= key_id < len(ck.keypairs)):
        raise ValueError(f"KeyID {key_id} out of range")

    kp = ck.keypairs[key_id]
    lamport_sig = lamport.sign(kp.sk, msg)
    path = merkle.make_path(ck.tree, key_id)

    ck.used.add(key_id)

    return Signature(key_id=key_id, lamport_sig=lamport_sig, path=path)


def verify(public_root: bytes, msg: bytes, sig: Signature) -> bool:
    """Verify a stateful signature against the composite public root.

    Verification has two independent checks, both of which must pass:
      1. The Lamport signature is valid under some public key PK.
         Since Lamport verification recomputes the claimed PK from the
         revealed hash chain outputs, we cannot just "trust" any PK — we
         reconstruct what PK *must* have been used for the Lamport sig to
         verify, then check step 2.
      2. That PK sits at position sig.key_id in the Merkle tree whose root
         is public_root.

    Implementation note: because our lamport.verify takes the full 2-D PK
    array, we reconstruct the PK from the signature and verify in one pass.
    """
    # Reconstruct the Lamport public key implied by this signature.
    # For each bit position i, the signature reveals one preimage; the
    # corresponding side of PK[i] must be H(TAG_LAMPORT_PK, sig_i). The
    # other side is unknown to the verifier — but it is committed to via
    # pk_digest over the whole PK, so we need both sides.
    #
    # Since the verifier does not have the unrevealed sides, we cannot
    # reconstruct the Lamport PK from the signature alone. We therefore
    # take a different route: the signature must be accompanied by the
    # Lamport PK itself, so the verifier can (a) check lamport.verify
    # and (b) hash the PK into a Merkle leaf and check the path.
    #
    # To keep the Signature struct minimal and faithful to the Kelsey
    # paper's signature layout, we accept that our Signature implicitly
    # depends on the PK. Concretely, this verify() needs access to the
    # one-time PK that produced sig.lamport_sig. In the single-signer
    # setting, the signer is expected to include the PK in the wire
    # format. We expose that via verify_with_pk below, and provide this
    # top-level verify() as a convenience that requires the caller to
    # supply the PK.
    raise NotImplementedError(
        "Use verify_with_pk; stateful verify needs the one-time PK supplied."
    )


def verify_with_pk(
    public_root: bytes,
    msg: bytes,
    sig: Signature,
    one_time_pk: list[list[bytes]],
) -> bool:
    """Verify a stateful signature, given the one-time PK used.

    This is the honest verification interface: a real serialized signature
    would include the one-time PK as part of its wire format. We keep it as
    a separate argument here so the in-memory Signature type stays clean.
    """
    # 1. The Lamport signature verifies under the claimed one-time PK.
    if not lamport.verify(one_time_pk, msg, sig.lamport_sig):
        return False

    # 2. The one-time PK, digested to a leaf, sits at sig.key_id under the root.
    leaf = lamport.pk_digest(one_time_pk)
    return merkle.verify_path(sig.path, leaf, public_root)