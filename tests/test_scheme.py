from dataclasses import replace

import pytest

import scalable_group_rekeying.scheme as scheme_module
from fake_scheme import BatchFakeScheme, BusyScheme, FakeScheme
from scalable_group_rekeying.crypto import KEY_LEN, public_key, sign, verify
from scalable_group_rekeying.scheme import RekeyScheme, make_scheme
from scalable_group_rekeying.types import (
    Batch,
    Epoch,
    Event,
    EventCost,
    EventKind,
    Fault,
    KeyRef,
    MemberId,
    RekeyMessage,
    SchemeConfig,
)

JOIN, LEAVE, REJOIN = EventKind.JOIN, EventKind.LEAVE, EventKind.REJOIN
M1, M2, M3, M4 = (MemberId(i) for i in range(1, 5))


def make_group(config: SchemeConfig | None = None) -> BatchFakeScheme:
    """An initialised group with members 1, 2 and 3."""
    group = BatchFakeScheme(config or SchemeConfig(seed=1))
    group.init([M1, M2, M3])
    return group


def make_batch(*changes: tuple[EventKind, int], t_apply: float = 0.0) -> Batch:
    events = tuple(
        Event(100 + i, kind, MemberId(member))
        for i, (kind, member) in enumerate(changes)
    )
    return Batch(events, t_apply)


def counted(scheme: RekeyScheme) -> EventCost:
    """Reads what the scheme's current counter has recorded."""
    batch = make_batch((JOIN, 1))
    return scheme.counter.finish(
        epoch=scheme.epoch, batch=batch, members_before=0, height=1, messages=()
    )


# ---------- init, apply and the single-event methods ----------


def test_init_creates_epoch_zero_from_a_batch_of_joins() -> None:
    group = FakeScheme(SchemeConfig(seed=1))

    outcome = group.init([M1, M2, M3])

    assert outcome.epoch == group.epoch == 0
    assert [(e.seq, e.kind, e.member) for e in outcome.batch.events] == [
        (0, JOIN, M1),
        (1, JOIN, M2),
        (2, JOIN, M3),
    ]
    assert outcome.batch.t_apply == 0.0
    assert (outcome.cost.n_joins, outcome.cost.members_before) == (3, 0)
    assert group.calls == ["init"]  # init() used _init, even without batch support


def test_init_cannot_be_called_twice() -> None:
    group = make_group()

    with pytest.raises(RuntimeError, match="already called"):
        group.init([M4])


def test_apply_needs_init_first() -> None:
    group = FakeScheme(SchemeConfig())

    with pytest.raises(RuntimeError, match="init"):
        group.join(M1)

    assert group.epoch == -1


@pytest.mark.parametrize("members", [[], [M1, M1], [MemberId(0)]])
def test_invalid_init_is_rejected_and_can_be_retried(members: list[MemberId]) -> None:
    group = FakeScheme(SchemeConfig())

    with pytest.raises(ValueError):
        group.init(members)

    assert group.epoch == -1
    assert group.init([M1]).epoch == 0


def test_join_leave_and_rejoin() -> None:
    group = FakeScheme(SchemeConfig(seed=1))
    group.init([M1, M2])

    joined = group.join(M3)
    left = group.leave(M3)
    rejoined = group.rejoin(M3)

    outcomes = (joined, left, rejoined)
    assert [o.epoch for o in outcomes] == [1, 2, 3]
    assert [o.batch.events[0].kind for o in outcomes] == [JOIN, LEAVE, REJOIN]
    assert [o.batch.events[0].seq for o in outcomes] == [2, 3, 4]
    assert [o.cost.members_before for o in outcomes] == [2, 3, 2]
    assert group.calls == ["init", "apply", "apply", "apply"]
    assert group.members() == {M1, M2, M3}


def test_next_seq_continues_after_the_highest_one_used() -> None:
    group = make_group()

    group.apply(Batch.single(Event(50, JOIN, M4)))

    assert group.leave(M4).batch.events[0].seq == 51


def test_outcome_holds_the_batch_and_signed_messages() -> None:
    group = make_group()
    batch = make_batch((LEAVE, 1), (JOIN, 4))

    outcome = group.apply(batch)

    assert outcome.batch is batch
    assert len(outcome.messages) == 1
    assert group._signature_ok(outcome.messages[0])
    assert outcome.cost.messages_multicast == 1
    assert (outcome.cost.n_joins, outcome.cost.n_leaves) == (1, 1)


def test_each_batch_starts_a_new_counter() -> None:
    group = BusyScheme(SchemeConfig(seed=1))

    first = group.init([M1, M2])
    second = group.join(M3)

    assert (first.cost.wraps, first.cost.unwraps) == (1, 2)
    assert (second.cost.wraps, second.cost.unwraps) == (1, 3)
    assert second.cost.modexp_total == 3


# ---------- validation ----------


@pytest.mark.parametrize(
    ("batch", "error"),
    [
        (Batch((), 0.0), "empty batch"),
        (make_batch((LEAVE, 1), (REJOIN, 1)), "appears twice"),
        (make_batch((JOIN, 1)), "invalid join"),  # current member
        (make_batch((JOIN, 3)), "invalid join"),  # former member must rejoin
        (make_batch((JOIN, 0)), "invalid join"),  # 0 means controller or broadcast
        (make_batch((LEAVE, 3)), "invalid leave"),  # former member
        (make_batch((LEAVE, 9)), "invalid leave"),  # never joined
        (make_batch((REJOIN, 1)), "invalid rejoin"),  # current member
        (make_batch((REJOIN, 9)), "invalid rejoin"),  # never joined
        (make_batch((JOIN, 4), (LEAVE, 9)), "invalid leave"),  # one bad event
        (Batch((Event(100, JOIN, M4, time=2.0),), 1.0), "after the batch"),
        (make_batch((LEAVE, 1), (LEAVE, 2)), "must remain"),
        (make_batch((LEAVE, 1), (LEAVE, 2), (JOIN, 4)), "must remain"),
    ],
)
def test_invalid_batch_is_rejected_without_changing_anything(
    batch: Batch, error: str
) -> None:
    group = make_group()
    group.leave(M3)  # leaves members 1 and 2, with 3 as a former member
    before = (group.epoch, group.members(), group._next_seq, list(group.calls))
    counter = group.counter

    with pytest.raises(ValueError, match=error):
        group.apply(batch)

    assert (group.epoch, group.members(), group._next_seq, group.calls) == before
    assert group.counter is counter
    assert group.signing_key(M4) is None


def test_most_members_can_be_replaced_if_one_remains() -> None:
    group = make_group()

    group.apply(make_batch((LEAVE, 1), (LEAVE, 2), (JOIN, 4)))

    assert group.members() == {M3, M4}


def test_scheme_without_batch_support_rejects_several_events() -> None:
    group = FakeScheme(SchemeConfig())
    group.init([M1, M2])

    with pytest.raises(ValueError, match="does not support batches"):
        group.apply(make_batch((JOIN, 3), (JOIN, 4)))

    assert group.epoch == 0


def test_unsupported_fault_is_rejected() -> None:
    with pytest.raises(ValueError, match="does not support fault"):
        FakeScheme(SchemeConfig(fault=Fault.SKIP_ANCESTOR))


# ---------- key rings and signing keys ----------


def test_rejoining_member_keeps_ring_and_signing_key() -> None:
    group = make_group()
    ring, key = group.keyring(M3), group.signing_key(M3)
    ring.learn(KeyRef(1, 0), b"old key", group.epoch)

    group.leave(M3)
    assert group.keyring(M3) is ring  # former members keep theirs

    group.rejoin(M3)
    assert group.keyring(M3) is ring
    assert ring.get(KeyRef(1, 0)) == b"old key"
    assert group.signing_key(M3) == key


def test_keyring_of_someone_who_never_joined_raises() -> None:
    with pytest.raises(KeyError):
        make_group().keyring(MemberId(9))


def test_each_member_and_the_controller_have_their_own_key_pair() -> None:
    group = make_group()
    privates = [group._signing_keys[owner] for owner in (None, M1, M2, M3)]

    assert len(set(privates)) == 4
    for owner, private in zip((None, M1, M2, M3), privates, strict=True):
        assert group.public_key(owner) == public_key(private)


def test_unknown_member_has_no_signing_keys() -> None:
    group = make_group()

    assert group.public_key(MemberId(9)) is None
    assert group.signing_key(MemberId(9)) is None


def test_controller_has_a_key_before_init() -> None:
    assert FakeScheme(SchemeConfig()).public_key(None) is not None


def test_signing_keys_follow_the_seed() -> None:
    same_a = make_group(SchemeConfig(seed=1))
    same_b = make_group(SchemeConfig(seed=1))
    different = make_group(SchemeConfig(seed=2))

    assert same_a.signing_key(M1) == same_b.signing_key(M1)
    assert same_a.signing_key(M1) != different.signing_key(M1)


# ---------- wrap, unwrap, modexp and node ids ----------


def test_wrap_and_unwrap_return_the_keys_in_order() -> None:
    group = make_group()
    wrapper_key, first, second = (group.keys.key() for _ in range(3))
    payloads = [(KeyRef(2, 0), first), (KeyRef(3, 0), second)]

    wrapped = group._wrap(KeyRef(1, 0), wrapper_key, payloads)

    assert wrapped.payloads == (KeyRef(2, 0), KeyRef(3, 0))
    assert group._unwrap(wrapped, wrapper_key, group.epoch) == (first, second)
    assert (counted(group).wraps, counted(group).unwraps) == (1, 1)


def test_failed_unwraps_return_none_and_are_not_counted() -> None:
    group = make_group()
    wrapper_key, payload_key = group.keys.key(), group.keys.key()
    wrapped = group._wrap(KeyRef(1, 0), wrapper_key, [(KeyRef(2, 0), payload_key)])
    relabelled = replace(wrapped, payloads=(KeyRef(9, 0),))

    assert group._unwrap(wrapped, payload_key, group.epoch) is None
    assert group._unwrap(wrapped, wrapper_key, Epoch(group.epoch + 1)) is None
    assert group._unwrap(relabelled, wrapper_key, group.epoch) is None
    assert counted(group).unwraps == 0


@pytest.mark.parametrize(
    "payloads", [[], [(KeyRef(2, 0), b"x" * (KEY_LEN - 1))]], ids=["none", "short"]
)
def test_wrap_rejects_bad_payloads(payloads: list[tuple[KeyRef, bytes]]) -> None:
    group = make_group()

    with pytest.raises(ValueError, match="KEY_LEN"):
        group._wrap(KeyRef(1, 0), group.keys.key(), payloads)

    assert counted(group).wraps == 0


@pytest.mark.parametrize("cache", [True, False])
def test_modexp_is_counted_for_every_member(cache: bool) -> None:
    group = make_group(SchemeConfig(cache=cache))

    results = [group._modexp(member, 4, 5, 23) for member in (M1, M1, M2)]

    assert results == [pow(4, 5, 23)] * 3
    assert (counted(group).modexp_total, counted(group).modexp_serial) == (3, 2)
    assert len(group._pow_cache) == (1 if cache else 0)


def test_node_ids_are_never_repeated() -> None:
    group = make_group()

    before = group._next_node()
    group.join(M4)

    assert group._next_node() > before


# ---------- signatures ----------


def test_signed_returns_a_signed_copy() -> None:
    group = make_group()
    message = RekeyMessage(group.epoch, sender=M1)

    signed = group._signed(message)

    assert message.signature == b""
    assert signed.signature
    assert group._signature_ok(signed)


@pytest.mark.parametrize("cache", [True, False])
def test_bad_signatures_are_rejected(cache: bool) -> None:
    group = make_group(SchemeConfig(cache=cache))
    signed = group._signed(RekeyMessage(group.epoch, sender=None))
    assert group._signature_ok(signed)  # the genuine one may now be cached

    altered = replace(signed, epoch=Epoch(9))  # copies the valid signature
    assert not group._signature_ok(altered)
    assert not group._signature_ok(replace(signed, sender=M1))
    assert not group._signature_ok(replace(signed, sender=MemberId(9)))
    assert not group._signature_ok(replace(signed, signature=b""))


def test_message_signed_by_another_key_is_rejected() -> None:
    group = make_group()
    message = RekeyMessage(group.epoch, sender=M1)
    key_of_m2 = group.signing_key(M2)
    assert key_of_m2 is not None
    forged = replace(message, signature=sign(key_of_m2, b"anything"))

    assert not group._signature_ok(forged)


def test_signing_can_be_turned_off() -> None:
    group = make_group(SchemeConfig(sign=False))
    message = RekeyMessage(group.epoch, sender=None)

    assert group._signed(message) is message
    assert group._signature_ok(message)


@pytest.mark.parametrize(("cache", "expected_calls"), [(True, 1), (False, 3)])
def test_cache_controls_how_often_a_message_is_verified(
    monkeypatch: pytest.MonkeyPatch, cache: bool, expected_calls: int
) -> None:
    group = make_group(SchemeConfig(cache=cache))
    signed = group._signed(RekeyMessage(group.epoch, sender=None))
    calls: list[bytes] = []

    def counting_verify(key: bytes, data: bytes, signature: bytes) -> bool:
        calls.append(data)
        return verify(key, data, signature)

    monkeypatch.setattr(scheme_module, "verify", counting_verify)

    assert all([group._signature_ok(signed) for _ in range(3)])
    assert len(calls) == expected_calls


def test_verification_cache_is_cleared_for_every_batch() -> None:
    group = make_group()
    group._signature_ok(group._signed(RekeyMessage(group.epoch, sender=None)))
    assert group._verified

    group.join(M4)

    assert not group._verified


def test_cache_changes_neither_messages_nor_costs() -> None:
    def run(cache: bool) -> list[tuple[tuple[RekeyMessage, ...], EventCost]]:
        group = BusyScheme(SchemeConfig(seed=7, cache=cache))
        outcomes = [group.init([M1, M2, M3]), group.leave(M2), group.rejoin(M2)]
        return [(o.messages, o.cost) for o in outcomes]

    assert run(cache=True) == run(cache=False)


# ---------- factory ----------


def test_factory_rejects_an_unknown_name() -> None:
    with pytest.raises(ValueError, match="unknown scheme"):
        make_scheme("unknown")


def test_factory_creates_a_registered_scheme(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(scheme_module._SCHEMES, "fake", "fake_scheme:FakeScheme")
    config = SchemeConfig(seed=3)

    default = make_scheme("fake")
    configured = make_scheme("fake", config)

    assert isinstance(default, FakeScheme)
    assert default.config == SchemeConfig()
    assert configured.config is config
