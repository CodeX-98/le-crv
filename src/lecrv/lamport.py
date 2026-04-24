"""Single-signer Lamport one-time signatures.

A Lamport secret key consists of 2n random n-bit values, arranged as n pairs.
The public key is the hash of each secret value, in the same shape.
To sign an n-bit message digest, for each bit i we reveal SK[i][bit_i].
The verifier hashes each revealed value and checks it matches PK[i][bit_i].

Each secret key MUST be used only once. Signing two messages with the same
key reveals enough of the secret to forge arbitrary signatures.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from lecrv.hashing import H, HASH_LEN, SEC_PARAM, TAG_LAMPORT_PK, hash_message

# A Lamport key for n-bit messages has 2n secret values of n bits each.
# With n = 256, that is 512 values of 32 bytes = 16 KiB per secret key.
NUM_BITS = HASH_LEN * 8  # 256 bit positions


@dataclass(frozen=True)
class LamportKeypair:
    """A Lamport keypair.

    sk[i][b] is the secret for bit position i, value b in {0, 1}.
    pk[i][b] is H(sk[i][b]).

    Both are stored as list[list[bytes]] with shape [NUM_BITS][2].
    """
    sk: list[list[bytes]]
    pk: list[list[bytes]]


def keygen(rng: callable = os.urandom) -> LamportKeypair:
    """Generate a fresh Lamport keypair.

    rng must be a callable taking an int byte count and returning that many
    random bytes. Default is os.urandom (cryptographically secure on Windows).
    For tests we override this with a deterministic source.
    """
    sk: list[list[bytes]] = [
        [rng(SEC_PARAM), rng(SEC_PARAM)] for _ in range(NUM_BITS)
    ]
    pk: list[list[bytes]] = [
        [H(TAG_LAMPORT_PK, sk[i][0]), H(TAG_LAMPORT_PK, sk[i][1])]
        for i in range(NUM_BITS)
    ]
    return LamportKeypair(sk=sk, pk=pk)


def _digest_bits(msg: bytes) -> list[int]:
    """Hash msg and return its 256 bits as a list of ints in {0, 1}.

    Bit ordering: for each byte, most-significant bit first. This is the
    convention used throughout the library; every call site must agree.
    """
    d = hash_message(msg)
    bits: list[int] = []
    for byte in d:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def sign(sk: list[list[bytes]], msg: bytes) -> list[bytes]:
    """Produce a Lamport signature on msg.

    The signature is a list of NUM_BITS values; the i-th value is sk[i][b_i]
    where b_i is the i-th bit of the hashed message.
    """
    bits = _digest_bits(msg)
    return [sk[i][bits[i]] for i in range(NUM_BITS)]


def verify(pk: list[list[bytes]], msg: bytes, sig: list[bytes]) -> bool:
    """Verify a Lamport signature.

    Recomputes the bit decomposition of hash(msg) and checks that for each
    bit position the signature value hashes to the corresponding public
    value. Returns True iff every position matches.
    """
    if len(sig) != NUM_BITS:
        return False
    bits = _digest_bits(msg)
    for i in range(NUM_BITS):
        if H(TAG_LAMPORT_PK, sig[i]) != pk[i][bits[i]]:
            return False
    return True


def pk_digest(pk: list[list[bytes]]) -> bytes:
    """Hash a Lamport public key down to a single 32-byte commitment.

    This is the value that will become a Merkle-tree leaf in the next step.
    We concatenate all 2 * NUM_BITS public values in canonical order and
    hash under the Lamport-PK tag.
    """
    flat = b"".join(pk[i][b] for i in range(NUM_BITS) for b in (0, 1))
    return H(TAG_LAMPORT_PK, flat)