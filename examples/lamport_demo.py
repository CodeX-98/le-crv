"""Minimal Lamport demo. Generates a keypair, signs, verifies."""

from lecrv.lamport import keygen, sign, verify, pk_digest


def main() -> None:
    kp = keygen()
    msg = b"hello, post-quantum world"

    sig = sign(kp.sk, msg)
    ok = verify(kp.pk, msg, sig)

    print(f"Public key digest: {pk_digest(kp.pk).hex()}")
    print(f"Message:           {msg!r}")
    print(f"Signature slots:   {len(sig)}")
    print(f"Signature bytes:   {sum(len(s) for s in sig)}")
    print(f"Verified:          {ok}")

    # Demonstrate rejection of a tampered message.
    ok_bad = verify(kp.pk, b"different message", sig)
    print(f"Bad msg verified:  {ok_bad}")


if __name__ == "__main__":
    main()