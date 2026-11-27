from dataclasses import fields, replace

import pytest

from scalable_group_rekeying.crypto import (
    KEY_LEN,
    NONCE_LEN,
    SIG_KEY_LEN,
    SIG_LEN,
    KeySource,
    derive_group_key,
    int_to_key,
    key_to_int,
    message_bytes,
    open_sealed,
    public_key,
    seal,
    sign,
    unwrap,
    verify,
    wrap,
    wrap_context,
    wrap_len,
)
from scalable_group_rekeying.types import (
    BlindedKey,
    Epoch,
    KeyRef,
    MemberId,
    RekeyMessage,
    Wrap,
)

KEY = b"k" * KEY_LEN
OTHER_KEY = b"o" * KEY_LEN
NONCE = b"n" * NONCE_LEN
CONTEXT = b"context"


# ---------- randomness ----------


def test_same_seed_gives_the_same_values() -> None:
    first, second = KeySource(1), KeySource(1)

    assert first.key() == second.key()
    assert first.nonce() == second.nonce()
    assert first.signing_key() == second.signing_key()
    assert first.exponent(10**18) == second.exponent(10**18)


@pytest.mark.parametrize("seed", [1, None])
def test_values_have_the_right_length_and_do_not_repeat(seed: int | None) -> None:
    source = KeySource(seed)

    for draw, length in (
        (source.key, KEY_LEN),
        (source.nonce, NONCE_LEN),
        (source.signing_key, SIG_KEY_LEN),
    ):
        first, second = draw(), draw()
        assert len(first) == len(second) == length
        assert first != second


def test_drawing_from_one_stream_does_not_change_another() -> None:
    plain, busy = KeySource(1), KeySource(1)

    busy.signing_key()
    busy.nonce()

    assert busy.key() == plain.key()


def test_exponent_stays_between_2_and_q_minus_1() -> None:
    source = KeySource(1)

    assert {source.exponent(5) for _ in range(200)} == {2, 3, 4}


# ---------- wraps ----------


def test_wrap_and_unwrap_round_trip() -> None:
    payload = b"p" * (2 * KEY_LEN)

    blob = wrap(KEY, payload, CONTEXT, NONCE)

    assert len(blob) == wrap_len(2)
    assert blob.startswith(NONCE)
    assert unwrap(KEY, blob, CONTEXT) == payload


def test_unwrap_fails_with_anything_wrong() -> None:
    blob = wrap(KEY, b"payload", CONTEXT, NONCE)
    tampered = blob[:-1] + bytes([blob[-1] ^ 1])

    assert unwrap(OTHER_KEY, blob, CONTEXT) is None
    assert unwrap(KEY, blob, b"other context") is None
    assert unwrap(KEY, tampered, CONTEXT) is None
    assert unwrap(KEY, blob[:5], CONTEXT) is None
    assert unwrap(b"short", blob, CONTEXT) is None


def test_wrap_rejects_a_wrong_nonce_length() -> None:
    with pytest.raises(ValueError, match="nonce"):
        wrap(KEY, b"payload", CONTEXT, NONCE + b"x")


def test_wrap_context_depends_on_every_label() -> None:
    a, b, c = KeyRef(1, 0), KeyRef(2, 0), KeyRef(3, 0)
    contexts = [
        wrap_context(a, (b, c), Epoch(1)),
        wrap_context(KeyRef(1, 1), (b, c), Epoch(1)),  # wrapper version
        wrap_context(b, (b, c), Epoch(1)),  # wrapper node
        wrap_context(a, (c, b), Epoch(1)),  # payload order
        wrap_context(a, (b,), Epoch(1)),  # payload count
        wrap_context(a, (b, c), Epoch(2)),  # epoch
    ]

    assert len(set(contexts)) == len(contexts)


# ---------- data messages ----------


def test_sealed_data_only_opens_in_its_epoch() -> None:
    blob = seal(KEY, b"hello", Epoch(1), NONCE)

    assert open_sealed(KEY, blob, Epoch(1)) == b"hello"
    assert open_sealed(KEY, blob, Epoch(2)) is None
    assert open_sealed(OTHER_KEY, blob, Epoch(1)) is None


def test_sealed_data_is_not_accepted_as_a_wrap() -> None:
    blob = seal(KEY, b"hello", Epoch(1), NONCE)
    context = wrap_context(KeyRef(1, 0), (KeyRef(2, 0),), Epoch(1))

    assert unwrap(KEY, blob, context) is None


# ---------- TGDH conversions ----------


def test_int_and_key_conversion_round_trip() -> None:
    assert int_to_key(258, 4) == b"\x00\x00\x01\x02"
    assert key_to_int(int_to_key(258, 4)) == 258


def test_derived_group_key_depends_on_secret() -> None:
    key = derive_group_key(12345)

    assert len(key) == KEY_LEN
    assert derive_group_key(12345) == key
    assert derive_group_key(12346) != key


# ---------- signatures ----------


def test_signature_verifies_only_for_the_same_key_and_data() -> None:
    source = KeySource(1)
    private, other = source.signing_key(), source.signing_key()

    signature = sign(private, b"data")

    assert len(signature) == SIG_LEN
    assert sign(private, b"data") == signature
    assert verify(public_key(private), b"data", signature)
    assert not verify(public_key(private), b"other data", signature)
    assert not verify(public_key(other), b"data", signature)
    assert not verify(b"not a public key", b"data", signature)


# ---------- message encoding ----------

REF_A, REF_B = KeyRef(1, 0), KeyRef(2, 0)
WRAP = Wrap(REF_A, (REF_B,), b"blob")
BLINDED = BlindedKey(REF_A, b"\x05", (REF_B,))
MESSAGE = RekeyMessage(
    Epoch(1), MemberId(1), MemberId(2), wraps=(WRAP,), blinded=(BLINDED,)
)


@pytest.mark.parametrize(
    "changed",
    [
        replace(MESSAGE, epoch=Epoch(2)),
        replace(MESSAGE, sender=None),
        replace(MESSAGE, recipient=None),
        replace(MESSAGE, wraps=()),
        replace(MESSAGE, wraps=(replace(WRAP, wrapper=REF_B),)),
        replace(MESSAGE, wraps=(replace(WRAP, payloads=(REF_A,)),)),
        replace(MESSAGE, wraps=(replace(WRAP, blob=b"blub"),)),
        replace(MESSAGE, blinded=()),
        replace(MESSAGE, blinded=(replace(BLINDED, node=REF_B),)),
        replace(MESSAGE, blinded=(replace(BLINDED, bk=b"\x06"),)),
        replace(MESSAGE, blinded=(replace(BLINDED, children=()),)),
        replace(MESSAGE, blinded=(replace(BLINDED, member=MemberId(3)),)),
    ],
)
def test_changing_any_signed_field_changes_the_bytes(changed: RekeyMessage) -> None:
    assert message_bytes(changed) != message_bytes(MESSAGE)


def test_signature_is_not_part_of_the_signed_bytes() -> None:
    assert message_bytes(replace(MESSAGE, signature=b"sig")) == message_bytes(MESSAGE)


def test_no_message_field_was_added_without_updating_the_encoding() -> None:
    """If this fails, add the new field to message_bytes, then to this test."""
    assert {f.name for f in fields(RekeyMessage)} == {
        "epoch",
        "sender",
        "recipient",
        "wraps",
        "blinded",
        "signature",
    }
    assert {f.name for f in fields(Wrap)} == {"wrapper", "payloads", "blob"}
    assert {f.name for f in fields(BlindedKey)} == {
        "node",
        "bk",
        "children",
        "member",
    }
