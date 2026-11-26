import json

import pytest

from scalable_group_rekeying.types import (
    DH_MODP,
    DH_TOY,
    Batch,
    DHParams,
    Epoch,
    EpochRecord,
    Event,
    EventKind,
    KeyRef,
    KeyRing,
    MemberId,
    NodeSnapshot,
    SchemeConfig,
    Snapshot,
    WrapEdge,
    to_jsonable,
)


def make_snapshot() -> Snapshot:
    """A root with two leaves, listed with the higher member id first."""
    return Snapshot(
        scheme="star",
        epoch=Epoch(1),
        root=0,
        nodes=(
            NodeSnapshot(0, None, (1, 2), None, 2, 1, "aaaaaaaa"),
            NodeSnapshot(1, 0, (), MemberId(7), 1, 0, "bbbbbbbb"),
            NodeSnapshot(2, 0, (), MemberId(3), 1, 0, "cccccccc"),
        ),
        viewer=None,
        last_event="join u7",
        wrap_edges=(WrapEdge(1, 0),),
    )


# ---------- key ring ----------


def test_key_ring_keeps_every_key_it_learned() -> None:
    ring = KeyRing(MemberId(1))
    old, new = KeyRef(1, 0), KeyRef(1, 1)

    ring.learn(old, b"old", Epoch(0))
    ring.learn(new, b"new", Epoch(1))

    assert ring.get(old) == b"old"
    assert ring.get(new) == b"new"
    assert ring.get(KeyRef(9, 0)) is None
    assert ring.ever_held() == {old: b"old", new: b"new"}
    assert [(a.ref, a.epoch) for a in ring.history] == [(old, 0), (new, 1)]


def test_ever_held_returns_a_copy() -> None:
    ring = KeyRing(MemberId(1))
    ring.learn(KeyRef(1, 0), b"key", Epoch(0))

    ring.ever_held().clear()

    assert ring.get(KeyRef(1, 0)) == b"key"


# ---------- batches, parameters, snapshots ----------


def test_single_batch_is_applied_at_the_event_time() -> None:
    event = Event(0, EventKind.JOIN, MemberId(1), time=3.5)

    assert Batch.single(event) == Batch((event,), 3.5)


@pytest.mark.parametrize("params", [DH_TOY, DH_MODP], ids=["toy", "modp"])
def test_dh_parameters_are_consistent(params: DHParams) -> None:
    assert params.p == 2 * params.q + 1
    assert params.alpha != 1
    assert pow(params.alpha, params.q, params.p) == 1  # alpha has order q


def test_snapshot_members_come_sorted_from_the_leaves() -> None:
    assert make_snapshot().members == (3, 7)


# ---------- to_jsonable ----------


def test_to_jsonable_converts_nested_snapshot_and_adds_members() -> None:
    result = to_jsonable(make_snapshot())

    assert isinstance(result, dict)
    assert result["members"] == [3, 7]
    assert result["nodes"][0]["children"] == [1, 2]
    assert result["wrap_edges"] == [{"wrapper": 1, "payload": 0}]
    assert result["cost"] is None
    assert json.loads(json.dumps(result)) == result


def test_to_jsonable_converts_enums_bytes_and_sets() -> None:
    event = Event(0, EventKind.LEAVE, MemberId(2))
    record = EpochRecord(
        epoch=Epoch(1),
        batch=Batch.single(event),
        members=frozenset({MemberId(30), MemberId(4), MemberId(1)}),
        group_ref=KeyRef(0, 1),
        group_key=b"\x00\xff",
    )

    result = to_jsonable(record)

    assert isinstance(result, dict)
    kind = result["batch"]["events"][0]["kind"]
    assert kind == "leave"
    assert type(kind) is str  # a plain string, not the enum member
    assert result["members"] == [1, 4, 30]
    assert result["group_key"] == "00ff"
    assert result["group_ref"] == {"node": 0, "version": 1}
    json.dumps(result)


@pytest.mark.parametrize(
    "value",
    [{"a": 1}, KeyRing(MemberId(1)), SchemeConfig, 1j],
    ids=["dict", "key_ring", "class", "complex"],
)
def test_to_jsonable_rejects_unsupported_types(value: object) -> None:
    with pytest.raises(TypeError):
        to_jsonable(value)


def test_to_jsonable_sends_large_integers_as_text() -> None:
    assert to_jsonable(2**53 - 1) == 2**53 - 1
    assert to_jsonable(2**53) == str(2**53)
