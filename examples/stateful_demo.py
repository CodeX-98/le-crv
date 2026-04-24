"""Stateful Lamport demo: one composite key signs multiple messages."""

from lecrv.stateful_lamport import keygen, sign, verify_with_pk


def main() -> None:
    D = 8
    ck = keygen(D)
    print(f"Generated composite key with D={D} one-time keys")
    print(f"Public root: {ck.public_root.hex()}\n")

    messages = [f"message {i}".encode() for i in range(5)]
    for msg in messages:
        sig = sign(ck, msg)
        pk = ck.keypairs[sig.key_id].pk
        ok = verify_with_pk(ck.public_root, msg, sig, pk)
        print(f"  KeyID {sig.key_id}: signed {msg!r} -> verified: {ok}")

    print(f"\nUsed KeyIDs: {sorted(ck.used)}")
    print(f"Remaining budget: {D - len(ck.used)} signatures")


if __name__ == "__main__":
    main()