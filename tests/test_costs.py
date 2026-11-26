from collections.abc import Sequence

from scalable_group_rekeying.costs import CostCounter
from scalable_group_rekeying.crypto import message_bytes
from scalable_group_rekeying.types import (
    Batch,
    Epoch,
    Event,
    EventCost,
    EventKind,
    KeyRef,
    MemberId,
    RekeyMessage,
    Wrap,
)


def finish(
    counter: CostCounter,
    messages: Sequence[RekeyMessage] = (),
    kinds: Sequence[EventKind] = (EventKind.JOIN,),
) -> EventCost:
    events = tuple(Event(i, kind, MemberId(i + 1)) for i, kind in enumerate(kinds))
    return counter.finish(
        epoch=Epoch(4),
        batch=Batch(events, t_apply=0.0),
        members_before=10,
        height=3,
        messages=messages,
    )


def test_a_new_counter_has_no_costs() -> None:
    cost = finish(CostCounter())

    assert (cost.wraps, cost.unwraps) == (0, 0)
    assert (cost.modexp_total, cost.modexp_serial) == (0, 0)
    assert (cost.messages_multicast, cost.messages_unicast) == (0, 0)
    assert (cost.key_encryptions, cost.bytes_on_wire) == (0, 0)


def test_given_values_are_passed_through() -> None:
    cost = finish(CostCounter())

    assert (cost.epoch, cost.members_before, cost.height) == (4, 10, 3)


def test_counts_wraps_and_unwraps() -> None:
    counter = CostCounter()

    counter.add_wrap()
    counter.add_unwrap()
    counter.add_unwrap()

    cost = finish(counter)
    assert (cost.wraps, cost.unwraps) == (1, 2)


def test_serial_modexps_are_the_most_done_by_one_member() -> None:
    counter = CostCounter()

    for member in (1, 1, 1, 2, 2, 3):
        counter.add_modexp(MemberId(member))

    cost = finish(counter)
    assert (cost.modexp_total, cost.modexp_serial) == (6, 3)


def test_rejoins_count_as_joins() -> None:
    kinds = (EventKind.JOIN, EventKind.REJOIN, EventKind.LEAVE)

    cost = finish(CostCounter(), kinds=kinds)

    assert (cost.n_joins, cost.n_leaves) == (2, 1)


def test_message_costs_are_derived_from_the_messages() -> None:
    ref = KeyRef(1, 0)
    multicast = RekeyMessage(
        Epoch(4),
        sender=None,
        wraps=(Wrap(ref, (ref, ref), b"first"), Wrap(ref, (ref,), b"second")),
        signature=b"s" * 64,
    )
    unicast = RekeyMessage(Epoch(4), sender=None, recipient=MemberId(1))

    cost = finish(CostCounter(), messages=[multicast, unicast])

    assert (cost.messages_multicast, cost.messages_unicast) == (1, 1)
    assert cost.key_encryptions == 3
    assert cost.wraps == 0  # counts encryption calls, not the wraps that were sent
    assert cost.bytes_on_wire == (
        len(message_bytes(multicast)) + 64 + len(message_bytes(unicast))
    )


def test_finish_does_not_change_the_counter() -> None:
    counter = CostCounter()
    counter.add_wrap()
    counter.add_modexp(MemberId(1))

    assert finish(counter) == finish(counter)
