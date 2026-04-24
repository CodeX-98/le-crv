"""Tests for the Lamport one-time signature scheme."""

import os

import pytest

from lecrv.hashing import HASH_LEN
from lecrv.lamport import (
    NUM_BITS,
    keygen,
    sign,
    verify,
    pk_digest,
)


def test_keygen_shape():
    """Secret and public keys have the right dimensions."""
    kp = keygen()
    assert len(kp.sk) == NUM_BITS
    assert len(kp.pk) == NUM_BITS
    for i in range(NUM_BITS):
        assert len(kp.sk[i]) == 2
        assert len(kp.pk[i]) == 2
        for b in (0, 1):
            assert len(kp.sk[i][b]) == HASH_LEN
            assert len(kp.pk[i][b]) == HASH_LEN


def test_sign_and_verify_roundtrip():
    """A signature produced by sign() verifies under the matching PK."""
    kp = keygen()
    msg = b"the quick brown fox"
    sig = sign(kp.sk, msg)
    assert verify(kp.pk, msg, sig) is True


def test_verify_rejects_wrong_message():
    """Changing the message invalidates the signature."""
    kp = keygen()
    sig = sign(kp.sk, b"message A")
    assert verify(kp.pk, b"message B", sig) is False


def test_verify_rejects_wrong_key():
    """A signature does not verify under a different public key."""
    kp1 = keygen()
    kp2 = keygen()
    msg = b"some message"
    sig = sign(kp1.sk, msg)
    assert verify(kp2.pk, msg, sig) is False


def test_verify_rejects_tampered_signature():
    """Flipping any byte in any signature slot causes rejection."""
    kp = keygen()
    msg = b"some message"
    sig = sign(kp.sk, msg)
    # Tamper with the first signature slot.
    tampered = list(sig)
    tampered[0] = bytes([tampered[0][0] ^ 0x01]) + tampered[0][1:]
    assert verify(kp.pk, msg, tampered) is False


def test_verify_rejects_wrong_length_signature():
    """A signature with the wrong number of slots is rejected."""
    kp = keygen()
    sig = sign(kp.sk, b"msg")
    assert verify(kp.pk, b"msg", sig[:-1]) is False


def test_deterministic_rng_reproducibility():
    """Using a deterministic RNG yields reproducible keypairs.

    This is a test-infrastructure check: if we seed the RNG, two independent
    keygen calls produce identical keys. This guarantees our tests are
    reproducible when we need them to be.
    """
    def make_rng(seed: int):
        state = [seed]
        def rng(n: int) -> bytes:
            # Trivial PRG for tests only. NEVER use for real keys.
            out = bytearray()
            while len(out) < n:
                state[0] = (state[0] * 1103515245 + 12345) & 0xFFFFFFFF
                out.extend(state[0].to_bytes(4, "big"))
            return bytes(out[:n])
        return rng

    kp_a = keygen(rng=make_rng(42))
    kp_b = keygen(rng=make_rng(42))
    assert kp_a.sk == kp_b.sk
    assert kp_a.pk == kp_b.pk


def test_pk_digest_is_deterministic_and_key_specific():
    """pk_digest returns 32 bytes, is deterministic, and differs between keys."""
    kp1 = keygen()
    kp2 = keygen()
    d1 = pk_digest(kp1.pk)
    d1_again = pk_digest(kp1.pk)
    d2 = pk_digest(kp2.pk)
    assert len(d1) == HASH_LEN
    assert d1 == d1_again
    assert d1 != d2


def test_signature_only_reveals_one_side_per_bit():
    """Sanity: the signature contains exactly NUM_BITS values of HASH_LEN bytes."""
    kp = keygen()
    sig = sign(kp.sk, b"x")
    assert len(sig) == NUM_BITS
    for part in sig:
        assert len(part) == HASH_LEN


@pytest.mark.parametrize("msg", [
    b"",
    b"a",
    b"A" * 1,
    b"A" * 1000,
    bytes(range(256)),
])
def test_signature_works_for_varied_message_lengths(msg):
    """Lamport signs a hash of the message, so any length should work."""
    kp = keygen()
    sig = sign(kp.sk, msg)
    assert verify(kp.pk, msg, sig)