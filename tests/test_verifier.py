from collections.abc import Sequence
from enum import Enum, auto

import pytest

from fake_scheme import FakeScheme
from scalable_group_rekeying.crypto import (
    KeySource,
    derive_group_key,
    int_to_key,
    seal,
    wrap,
    wrap_context,
)
from scalable_group_rekeying.scheme import DeliveryResult, RekeyScheme
from scalable_group_rekeying.simulator import Simulator
from scalable_group_rekeying.types import (
    DH_MODP,
    DH_TOY,
    Batch,
    BlindedKey,
    DataMessage,
    DHParams,
    Epoch,
    EpochRecord,
    Event,
    EventKind,
    KeyRef,
    KeyRing,
    MemberId,
    RekeyMessage,
    SchemeConfig,
    Snapshot,
    Transcript,
    Wrap,
)
from scalable_group_rekeying.verifier import (
    Check,
    Verifier,
    can_read,
    check_key_reuse,
    check_secrecy,
    check_state,
    closure,
)

JOIN, LEAVE, REJOIN = EventKind.JOIN, EventKind.LEAVE, EventKind.REJOIN
M1, M2, M3, M4, M5 = (MemberId(i) for i in range(1, 6))
KEY_A, KEY_B, KEY_C = (letter * 32 for letter in (b"a", b"b", b"c"))
GROUPS = pytest.mark.parametrize("dh", [DH_TOY, DH_MODP], ids=["toy", "modp"])

Found = set[tuple[Check, MemberId | None, int]]


# ---------- a small Star scheme that can be broken on purpose ----------


class Bug(Enum):
    NONE = auto()
    SEND_TO_LEAVER = auto()  # the new group key also goes to whoever just left
    KEEP_GROUP_KEY = auto()  # the group key never changes after epoch 0
    SKIP_A_MEMBER = auto()  # after epoch 0, the lowest member id gets nothing


class ToyStar(RekeyScheme):
    """Just enough of a Star scheme to give the verifier real runs to judge.

    Not a reference implementation: deliver() skips the checks a real one must do."""

    name = "star"
    supports_batch = True

    def __init__(self, bug: Bug = Bug.NONE) -> None:
        super().__init__(SchemeConfig(seed=1))
        self.bug = bug
        self.current: set[MemberId] = set()
        self.individual: dict[MemberId, tuple[KeyRef, bytes]] = {}
        self.believed: dict[MemberId, tuple[KeyRef, bytes]] = {}
        self.root = KeyRef(self._next_node(), 0)
        self.root_key = b""

    def _init(self, batch: Batch) -> Sequence[RekeyMessage]:
        return self._change(batch)

    def _apply(self, batch: Batch) -> Sequence[RekeyMessage]:
        return self._change(batch)

    def _change(self, batch: Batch) -> Sequence[RekeyMessage]:
        left: set[MemberId] = set()
        for event in batch.events:
            m = event.member
            if event.kind == LEAVE:
                self.current.remove(m)
                left.add(m)
            else:
                self.current.add(m)
                self.individual[m] = (KeyRef(self._next_node(), 0), self.keys.key())
                self.keyring(m).learn(*self.individual[m], self.epoch)

        if self.epoch == 0 or self.bug != Bug.KEEP_GROUP_KEY:
            self.root = KeyRef(self.root.node, self.epoch)
            self.root_key = self.keys.key()

        recipients = set(self.current)
        if self.bug == Bug.SEND_TO_LEAVER:
            recipients |= left
        if self.bug == Bug.SKIP_A_MEMBER and self.epoch > 0:
            recipients.remove(min(recipients))

        messages = []
        for m in sorted(recipients):
            wrapped = self._wrap(*self.individual[m], [(self.root, self.root_key)])
            message = self._signed(
                RekeyMessage(self.epoch, sender=None, recipient=m, wraps=(wrapped,))
            )
            messages.append(message)
            self.deliver(m, message)
        return messages

    def deliver(self, member: MemberId, msg: RekeyMessage) -> DeliveryResult:
        ring = self.keyring(member)
        learned: list[KeyRef] = []
        for w in msg.wraps:
            key = ring.get(w.wrapper)
            if key is None:
                continue
            opened = self._unwrap(w, key, msg.epoch)
            if opened is None:
                continue
            ref = w.payloads[0]
            ring.learn(ref, opened[0], msg.epoch)
            self.believed[member] = (ref, opened[0])
            learned.append(ref)
        return DeliveryResult(bool(learned), tuple(learned))

    def members(self) -> frozenset[MemberId]:
        return frozenset(self.current)

    def group_key(self) -> tuple[KeyRef, bytes]:
        return self.root, self.root_key

    def member_group_key(self, member: MemberId) -> tuple[KeyRef, bytes] | None:
        return self.believed.get(member)

    def height(self) -> int:
        return 1

    def snapshot(self, viewer: MemberId | None = None) -> Snapshot:
        raise NotImplementedError


def run(
    bug: Bug = Bug.NONE, *, secrecy_every_event: bool = True
) -> tuple[Simulator, Verifier]:
    """Members per epoch: 0 {1234}, 1 {134}, 2 {1345}, 3 {12345}, 4 {2345}."""
    verifier = Verifier(secrecy_every_event=secrecy_every_event)
    simulator = Simulator(ToyStar(bug), [verifier])
    simulator.init([M1, M2, M3, M4])
    changes = [(LEAVE, M2), (JOIN, M5), (REJOIN, M2), (LEAVE, M1)]
    for i, (kind, member) in enumerate(changes):
        simulator.apply(Batch.single(Event(10 + i, kind, member)))
    return simulator, verifier


def found(verifier: Verifier) -> Found:
    return {(v.check, v.member, v.epoch) for v in verifier.violations}


def rings_of(simulator: Simulator) -> list[KeyRing]:
    return [simulator.scheme.keyring(m) for m in (M1, M2, M3, M4, M5)]


# ---------- closure ----------


def make_wrap(
    keys: KeySource,
    wrapper: KeyRef,
    wrapper_key: bytes,
    payload: tuple[KeyRef, bytes],
    epoch: Epoch,
) -> Wrap:
    ref, key = payload
    context = wrap_context(wrapper, (ref,), epoch)
    return Wrap(wrapper, (ref,), wrap(wrapper_key, key, context, keys.nonce()))


def chain_transcript() -> Transcript:
    """A opens B and B opens C, with the second step sent first. The wrap under B
    also names the wrong wrapper."""
    keys = KeySource(1)
    first = make_wrap(keys, KeyRef(1, 0), KEY_A, (KeyRef(2, 0), KEY_B), Epoch(1))
    second = make_wrap(keys, KeyRef(99, 0), KEY_B, (KeyRef(3, 0), KEY_C), Epoch(2))
    return Transcript(
        rekeys=[
            RekeyMessage(Epoch(2), sender=None, wraps=(second,)),
            RekeyMessage(Epoch(1), sender=None, wraps=(first,)),
        ]
    )


def test_closure_follows_a_chain_whatever_the_order_and_refs_say() -> None:
    assert closure([KEY_A], chain_transcript(), DH_TOY) == {KEY_A, KEY_B, KEY_C}


@pytest.mark.parametrize("known", [[], [b"x" * 32]], ids=["nothing", "unrelated"])
def test_closure_learns_nothing_without_a_useful_key(known: list[bytes]) -> None:
    assert closure(known, chain_transcript(), DH_TOY) == set(known)


@GROUPS
def test_closure_climbs_a_tgdh_tree(dh: DHParams) -> None:
    """The tree is ((1, 2), 3), with every blinded key published."""
    keys = KeySource(2)
    length = (dh.p.bit_length() + 7) // 8
    x1, x2, x3, outsider = (keys.exponent(dh.q) for _ in range(4))
    x12 = pow(pow(dh.alpha, x2, dh.p), x1, dh.p)
    root = pow(pow(dh.alpha, x3, dh.p), x12, dh.p)

    def stored(x: int) -> bytes:
        return int_to_key(x, length)

    def blinded(node: int, x: int, *children: int) -> BlindedKey:
        return BlindedKey(
            KeyRef(node, 0),
            stored(pow(dh.alpha, x, dh.p)),
            tuple(KeyRef(child, 0) for child in children),
        )

    tree = (
        blinded(1, x1),
        blinded(2, x2),
        blinded(3, x3),
        blinded(4, x12, 1, 2),
        blinded(5, root, 4, 3),
    )
    transcript = Transcript(rekeys=[RekeyMessage(Epoch(0), sender=M1, blinded=tree)])

    for x in (x1, x2):
        expected = {stored(x), stored(x12), stored(root)}
        assert closure([stored(x)], transcript, dh) == expected
    assert closure([stored(x3)], transcript, dh) == {stored(x3), stored(root)}
    assert closure([stored(outsider)], transcript, dh) == {stored(outsider)}


# ---------- can_read ----------


def sealed(key: bytes, epoch: int) -> DataMessage:
    nonce = KeySource(3).nonce()
    return DataMessage(Epoch(epoch), seal(key, b"probe", Epoch(epoch), nonce))


def test_can_read_needs_the_right_key() -> None:
    data = sealed(KEY_A, 3)

    assert can_read([KEY_B, b"", KEY_A], data)
    assert not can_read([KEY_B, b""], data)
    assert not can_read([], data)


def test_can_read_checks_the_epoch() -> None:
    relabelled = DataMessage(Epoch(4), sealed(KEY_A, 3).blob)

    assert not can_read([KEY_A], relabelled)


@GROUPS
@pytest.mark.parametrize("root", [5, 2**60 + 7], ids=["leading zeros", "large"])
def test_can_read_derives_the_group_key_from_a_tgdh_secret(
    dh: DHParams, root: int
) -> None:
    length = (dh.p.bit_length() + 7) // 8
    data = sealed(derive_group_key(root), 1)

    assert can_read([int_to_key(root, length)], data)
    assert not can_read([int_to_key(root + 1, length)], data)


# ---------- check_state ----------


GOOD = (KeyRef(0, 3), KEY_A)


class StateScheme(FakeScheme):
    """Reports whatever members and group keys the test gives it."""

    def __init__(
        self,
        members: set[MemberId],
        believed: dict[MemberId, tuple[KeyRef, bytes]],
    ) -> None:
        super().__init__(SchemeConfig(seed=1))
        self.current = members
        self.believed = believed

    def member_group_key(self, member: MemberId) -> tuple[KeyRef, bytes] | None:
        return self.believed.get(member)


def state_findings(
    recorded: set[MemberId],
    actual: set[MemberId],
    believed: dict[MemberId, tuple[KeyRef, bytes]],
) -> list[tuple[Check, MemberId | None, str]]:
    record = EpochRecord(Epoch(3), Batch((), 0.0), frozenset(recorded), *GOOD)
    violations = check_state(StateScheme(actual, believed), record)
    return [(v.check, v.member, v.detail) for v in violations]


def test_check_state_accepts_a_correct_group() -> None:
    believed = {M1: GOOD, M2: GOOD, M3: (KeyRef(0, 1), KEY_B)}  # M3 left earlier

    assert state_findings({M1, M2}, {M1, M2}, believed) == []


def test_check_state_reports_an_extra_member() -> None:
    assert state_findings({M1}, {M1, M2}, {M1: GOOD}) == [
        (Check.MEMBERSHIP, M2, "in the scheme but not in the group")
    ]


def test_check_state_still_checks_a_member_the_scheme_forgot() -> None:
    assert state_findings({M1, M2}, {M1}, {M1: GOOD}) == [
        (Check.MEMBERSHIP, M2, "missing from the scheme"),
        (Check.AGREEMENT, M2, "has no group key"),
    ]


def test_check_state_reports_an_old_ref_and_a_wrong_key() -> None:
    believed = {M1: (KeyRef(0, 2), KEY_A), M2: (KeyRef(0, 3), KEY_B)}

    assert state_findings({M1, M2}, {M1, M2}, believed) == [
        (
            Check.AGREEMENT,
            M1,
            "has KeyRef(node=0, version=2), expected KeyRef(node=0, version=3)",
        ),
        (Check.AGREEMENT, M2, "has the wrong key for KeyRef(node=0, version=3)"),
    ]


# ---------- check_key_reuse ----------


def make_ring(member: MemberId, *learned: tuple[KeyRef, bytes, int]) -> KeyRing:
    ring = KeyRing(member)
    for ref, key, epoch in learned:
        ring.learn(ref, key, Epoch(epoch))
    return ring


def record_with_key(epoch: int, key: bytes) -> EpochRecord:
    return EpochRecord(Epoch(epoch), Batch((), 0.0), frozenset(), KeyRef(0, epoch), key)


def reuse_findings(
    rings: Sequence[KeyRing], epochs: Sequence[EpochRecord] = ()
) -> list[tuple[int, str]]:
    return [(v.epoch, v.detail) for v in check_key_reuse(rings, epochs)]


def test_sharing_and_relearning_a_key_is_not_reuse() -> None:
    ref = KeyRef(0, 0)
    rings = [
        make_ring(M1, (ref, KEY_A, 0), (ref, KEY_A, 3)),
        make_ring(M2, (ref, KEY_A, 0)),
    ]

    assert reuse_findings(rings) == []


def test_a_tgdh_record_may_differ_from_the_ring_under_the_same_ref() -> None:
    """The ring has the root secret, the record has the key derived from it."""
    rings = [make_ring(M1, (KeyRef(0, 0), KEY_A, 0))]

    assert reuse_findings(rings, [record_with_key(0, KEY_B)]) == []


def test_one_ref_with_two_values_is_reported_whatever_the_ring_order() -> None:
    ref = KeyRef(1, 0)
    rings = [make_ring(M1, (ref, KEY_A, 0)), make_ring(M2, (ref, KEY_B, 2))]
    expected = [(2, "KeyRef(node=1, version=0) has more than one value")]

    assert reuse_findings(rings) == expected
    assert reuse_findings(rings[::-1]) == expected


def test_one_value_under_two_refs_stays_the_same_finding_as_history_grows() -> None:
    ring = make_ring(M1, (KeyRef(1, 0), KEY_A, 0), (KeyRef(1, 1), KEY_A, 4))
    before = check_key_reuse([ring], [])

    ring.learn(KeyRef(5, 0), KEY_C, Epoch(6))

    assert check_key_reuse([ring], []) == before
    assert [(v.epoch, v.member, v.detail) for v in before] == [
        (
            4,
            None,
            "KeyRef(node=1, version=1) has the same value as KeyRef(node=1, version=0)",
        )
    ]


def test_a_group_key_shared_by_two_epochs_is_reported() -> None:
    epochs = [record_with_key(e, key) for e, key in enumerate([KEY_A, KEY_B, KEY_A])]

    assert reuse_findings([], epochs) == [(2, "same group key as epoch 0")]


# ---------- check_secrecy ----------


def secrecy_findings(simulator: Simulator, rings: Sequence[KeyRing]) -> Found:
    violations = check_secrecy(rings, simulator.transcript, simulator.epochs, DH_TOY)
    return {(v.check, v.member, v.epoch) for v in violations}


def test_check_secrecy_uses_every_value_a_person_ever_held() -> None:
    """A second value under the same ref must not hide the first one."""
    simulator, _ = run()
    ring = simulator.scheme.keyring(M2)
    ref = KeyRef(1000, 0)
    ring.learn(ref, simulator.epochs[1].group_key, Epoch(1))  # M2 had left
    ring.learn(ref, KEY_A, Epoch(3))

    assert secrecy_findings(simulator, [ring]) == {(Check.SECRECY, M2, 1)}


def test_check_secrecy_only_checks_the_rings_it_is_given() -> None:
    simulator, _ = run(Bug.SEND_TO_LEAVER)

    assert secrecy_findings(simulator, rings_of(simulator)[2:]) == set()


def test_a_missing_probe_is_an_error() -> None:
    simulator, _ = run()
    del simulator.transcript.data[1]

    with pytest.raises(ValueError, match="no probe"):
        secrecy_findings(simulator, rings_of(simulator))


def test_a_second_probe_for_an_epoch_is_an_error() -> None:
    simulator, _ = run()
    simulator.transcript.data.append(sealed(KEY_A, 1))

    with pytest.raises(ValueError, match="more than one probe"):
        secrecy_findings(simulator, rings_of(simulator))


# ---------- the verifier during a simulation ----------


EXPECTED: dict[Bug, Found] = {
    Bug.NONE: set(),
    Bug.SEND_TO_LEAVER: {(Check.SECRECY, M2, 1), (Check.SECRECY, M1, 4)},
    Bug.KEEP_GROUP_KEY: {
        *((Check.KEY_REUSE, None, epoch) for epoch in (1, 2, 3, 4)),
        (Check.SECRECY, M1, 4),  # after leaving
        (Check.SECRECY, M2, 1),  # between two stints
        (Check.SECRECY, M2, 2),
        (Check.SECRECY, M5, 0),  # before joining
        (Check.SECRECY, M5, 1),
    },
    Bug.SKIP_A_MEMBER: {
        (check, member, epoch)
        for check in (Check.AGREEMENT, Check.REACHABILITY)
        for member, epoch in ((M1, 1), (M1, 2), (M1, 3), (M2, 4))
    },
}


@pytest.mark.parametrize("bug", Bug, ids=lambda bug: bug.name.lower())
def test_verifier_reports_exactly_what_is_broken(bug: Bug) -> None:
    _, verifier = run(bug)

    assert found(verifier) == EXPECTED[bug]
    assert len(verifier.violations) == len(EXPECTED[bug])  # no finding kept twice


@pytest.mark.parametrize("bug", Bug, ids=lambda bug: bug.name.lower())
def test_checking_history_at_the_end_finds_the_same(bug: Bug) -> None:
    _, every_event = run(bug)
    simulator, at_end = run(bug, secrecy_every_event=False)
    state_checks = {Check.MEMBERSHIP, Check.AGREEMENT}
    assert {v.check for v in at_end.violations} <= state_checks

    at_end.check_history(simulator.scheme, simulator.transcript, simulator.epochs)

    assert at_end.violations == every_event.violations
