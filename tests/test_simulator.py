import hashlib
from collections.abc import Sequence

import pytest

from fake_scheme import BatchFakeScheme, BusyScheme
from scalable_group_rekeying.crypto import NONCE_LEN, open_sealed
from scalable_group_rekeying.scheme import RekeyOutcome, RekeyScheme
from scalable_group_rekeying.simulator import Observer, Simulator
from scalable_group_rekeying.types import (
    Batch,
    EpochRecord,
    Event,
    EventKind,
    KeyRef,
    MemberId,
    RekeyMessage,
    SchemeConfig,
    Transcript,
)

JOIN, LEAVE, REJOIN = EventKind.JOIN, EventKind.LEAVE, EventKind.REJOIN
M1, M2, M3, M4 = (MemberId(i) for i in range(1, 5))


class KeyedScheme(BatchFakeScheme):
    """Adds what the simulator needs: a different group key at every epoch."""

    def group_key(self) -> tuple[KeyRef, bytes]:
        key = hashlib.sha256(f"group {self.epoch}".encode()).digest()
        return KeyRef(0, self.epoch), key


class BusyKeyedScheme(KeyedScheme, BusyScheme):
    """KeyedScheme that also wraps keys, so it uses nonces."""


class ForgetfulScheme(KeyedScheme):
    """Broken on purpose: its own member list ignores every change."""

    def _apply(self, batch: Batch) -> Sequence[RekeyMessage]:
        return [self._signed(RekeyMessage(self.epoch, sender=None))]


def make_batch(*changes: tuple[EventKind, MemberId]) -> Batch:
    events = tuple(
        Event(100 + i, kind, member) for i, (kind, member) in enumerate(changes)
    )
    return Batch(events, t_apply=0.0)


def make_simulator(
    scheme: RekeyScheme | None = None, observers: Sequence[Observer] = ()
) -> Simulator:
    """A simulator that has not been initialised yet."""
    return Simulator(scheme or KeyedScheme(SchemeConfig(seed=1)), observers)


# ---------- what gets recorded ----------


def test_init_records_epoch_zero() -> None:
    simulator = make_simulator()

    outcome = simulator.init([M1, M2, M3])

    [record] = simulator.epochs
    assert (record.epoch, record.batch) == (0, outcome.batch)
    assert record.members == {M1, M2, M3}
    assert (record.group_ref, record.group_key) == simulator.scheme.group_key()
    assert simulator.transcript.rekeys == list(outcome.messages)
    assert len(simulator.transcript.data) == 1


def test_every_batch_adds_a_record_and_its_messages_in_order() -> None:
    simulator = make_simulator()
    first = simulator.init([M1, M2, M3])

    outcomes = simulator.run(
        [make_batch((LEAVE, M2), (JOIN, M4)), make_batch((REJOIN, M2))]
    )

    assert [o.epoch for o in outcomes] == [1, 2]
    assert [r.epoch for r in simulator.epochs] == [0, 1, 2]
    assert [r.members for r in simulator.epochs] == [
        {M1, M2, M3},
        {M1, M3, M4},
        {M1, M2, M3, M4},
    ]
    sent = [m for o in (first, *outcomes) for m in o.messages]
    assert simulator.transcript.rekeys == sent


def test_members_are_replayed_from_the_events_not_read_from_the_scheme() -> None:
    simulator = make_simulator(ForgetfulScheme(SchemeConfig(seed=1)))
    simulator.init([M1, M2, M3])

    simulator.apply(make_batch((LEAVE, M2)))
    # The broken scheme still lists member 2, so it accepts a second leave
    simulator.apply(make_batch((LEAVE, M2)))

    assert simulator.scheme.members() == {M1, M2, M3}
    assert [r.members for r in simulator.epochs[1:]] == [{M1, M3}, {M1, M3}]

    # ---------- probe messages ----------


def test_each_probe_opens_only_with_the_key_of_its_epoch() -> None:
    simulator = make_simulator()
    simulator.init([M1, M2])
    simulator.run([make_batch((JOIN, M3)), make_batch((LEAVE, M1))])

    data = simulator.transcript.data
    assert [d.epoch for d in data] == [0, 1, 2]
    for message in data:
        for record in simulator.epochs:
            opened = open_sealed(record.group_key, message.blob, message.epoch)
            own = record.epoch == message.epoch
            assert opened == (f"probe {message.epoch}".encode() if own else None)


def test_probes_never_reuse_a_nonce_or_count_as_rekeying() -> None:
    simulator = make_simulator(BusyKeyedScheme(SchemeConfig(seed=1)))
    simulator.init([M1, M2])

    outcome = simulator.apply(make_batch((JOIN, M3)))

    wraps = [w for m in simulator.transcript.rekeys for w in m.wraps]
    sealed: list[bytes] = [w.blob for w in wraps]
    sealed += [d.blob for d in simulator.transcript.data]
    nonces = [blob[:NONCE_LEN] for blob in sealed]
    assert len(set(nonces)) == len(nonces) == 4
    assert simulator.scheme.counter._wraps == outcome.cost.wraps == 1


def test_the_same_seed_gives_the_same_run() -> None:
    def run() -> Simulator:
        simulator = make_simulator(BusyKeyedScheme(SchemeConfig(seed=7)))
        simulator.init([M1, M2])
        simulator.run([make_batch((JOIN, M3)), make_batch((LEAVE, M2))])
        return simulator

    first, second = run(), run()

    assert first.transcript == second.transcript
    assert first.epochs == second.epochs


# ---------- errors ----------


@pytest.mark.parametrize("initialised_outside", [False, True])
def test_apply_needs_the_simulator_to_be_initialised(
    initialised_outside: bool,
) -> None:
    scheme = KeyedScheme(SchemeConfig(seed=1))
    if initialised_outside:
        scheme.init([M1, M2])
    simulator = make_simulator(scheme)
    epoch_before = scheme.epoch

    with pytest.raises(RuntimeError, match="init"):
        simulator.apply(make_batch((JOIN, M3)))

    assert scheme.epoch == epoch_before
    assert not simulator.epochs
    assert simulator.transcript == Transcript()


def test_changing_the_scheme_directly_is_detected() -> None:
    simulator = make_simulator()
    simulator.init([M1, M2])
    simulator.scheme.join(M3)  # the simulator doesn't see this one

    with pytest.raises(RuntimeError, match="outside the simulator"):
        simulator.apply(make_batch((JOIN, M4)))

    assert len(simulator.epochs) == 1


def test_run_stops_at_a_bad_batch_and_keeps_the_earlier_ones() -> None:
    simulator = make_simulator()
    simulator.init([M1, M2])
    batches = [
        make_batch((JOIN, M3)),
        make_batch((LEAVE, M4)),  # never joined
        make_batch((LEAVE, M1)),
    ]

    with pytest.raises(ValueError, match="invalid leave"):
        simulator.run(batches)

    assert [r.members for r in simulator.epochs] == [{M1, M2}, {M1, M2, M3}]
    assert len(simulator.transcript.rekeys) == 2
    assert len(simulator.transcript.data) == 2


# ---------- observers ----------


class Spy:
    """Notes how much had been recorded each time it was called."""

    def __init__(self, name: str, log: list[tuple[str, int, int, int, int]]) -> None:
        self.name = name
        self.log = log

    def after_apply(
        self,
        scheme: RekeyScheme,
        outcome: RekeyOutcome,
        transcript: Transcript,
        epochs: Sequence[EpochRecord],
    ) -> None:
        assert scheme.epoch == outcome.epoch == epochs[-1].epoch
        recorded = (len(transcript.rekeys), len(transcript.data), len(epochs))
        self.log.append((self.name, outcome.epoch, *recorded))


def test_observers_are_called_in_order_once_everything_is_recorded() -> None:
    log: list[tuple[str, int, int, int, int]] = []
    simulator = make_simulator(observers=[Spy("a", log), Spy("b", log)])

    simulator.init([M1, M2])
    simulator.apply(make_batch((JOIN, M3)))

    assert log == [
        ("a", 0, 1, 1, 1),
        ("b", 0, 1, 1, 1),
        ("a", 1, 2, 2, 2),
        ("b", 1, 2, 2, 2),
    ]
