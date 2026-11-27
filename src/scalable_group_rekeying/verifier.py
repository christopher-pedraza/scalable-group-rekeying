# @Chris
# @Chris
"""Checks a run from the outside. Never imports a scheme or the simulator."""

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from scalable_group_rekeying.crypto import (
    KEY_LEN,
    derive_group_key,
    int_to_key,
    key_to_int,
    open_sealed,
    unwrap,
    wrap_context,
)
from scalable_group_rekeying.scheme import RekeyOutcome, RekeyScheme
from scalable_group_rekeying.types import (
    DataMessage,
    DHParams,
    Epoch,
    EpochRecord,
    KeyRef,
    KeyRing,
    MemberId,
    Transcript,
)


class Check(StrEnum):
    MEMBERSHIP = "membership"  # scheme's members differ from the replayed events
    AGREEMENT = "agreement"  # a current member lacks the right group key
    KEY_REUSE = "key_reuse"  # a key or a ref was used twice
    SECRECY = "secrecy"  # someone reads an epoch they weren't a member in
    REACHABILITY = "reachability"  # a member can't read their own epoch


@dataclass(frozen=True, slots=True)
class Violation:
    check: Check
    epoch: Epoch  # the affected epoch
    member: MemberId | None  # None if it isn't about one person
    detail: str  # deterministic, so repeated findings compare equal


# ---------- what an adversary can compute ----------


def _sibling_bks(transcript: Transcript) -> dict[int, set[int]]:
    """Maps each child's blinded key to the blinded keys of its siblings."""
    published: defaultdict[KeyRef, set[int]] = defaultdict(set)
    pairs: set[tuple[KeyRef, ...]] = set()

    # Collect the blinded key(s) published for each node, and each parent's children
    for msg in transcript.rekeys:
        for b in msg.blinded:
            published[b.node].add(key_to_int(b.bk))
            if len(b.children) == 2:
                pairs.add(b.children)

    # Replaces the node refs from 'pairs' with the blinded key. Add both directions of
    # the sibling relationship because either children can compute the parent key)
    siblings: defaultdict[int, set[int]] = defaultdict(set)
    for left, right in pairs:
        # In the ideal scenario, the following loops just run once because a node's
        # version is bumped every time its key changes. However, as this is the
        # verifier, we cannot assume a perfect scheme, we could have a buggy sponsor
        # that changes its secret but forgets to bump the version.
        for left_bk in published.get(left, ()):
            for right_bk in published.get(right, ()):
                siblings[left_bk].add(right_bk)
                siblings[right_bk].add(left_bk)
    return dict(siblings)


def closure(
    known: Iterable[bytes], transcript: Transcript, dh: DHParams
) -> frozenset[bytes]:
    """Compute the closure of the known values under the operations of unwrap and DH."""
    # Map all the wraps with the epoch they were sent in
    wraps = [(msg.epoch, w) for msg in transcript.rekeys for w in msg.wraps]
    siblings = _sibling_bks(transcript)
    secret_len = (dh.p.bit_length() + 7) // 8

    found = set(known)  # everything known so far
    todo = list(found)  # values whose values haven't been yet tried

    # The loop will go through both wraps and siblings so it's scheme agnostic. It
    # doesn't need to know if the transcript belongs to Star/LKH (has wraps) or TGDH
    # (has siblings)
    while todo:
        value = todo.pop()
        derived: list[bytes] = []

        # we try the value on every wrap that is still closed. Even if w.wrapper
        # specifies which key should open it, as this code is verifying the scheme, we
        # still try every value on every wrap
        closed = []
        for epoch, w in wraps:
            # The context is public but needed for decryption. A succesful tag check
            # means the key was right
            context = wrap_context(w.wrapper, w.payloads, epoch)
            plaintext = unwrap(value, w.blob, context)
            # if the value didn't open this wrap, keep it for later. Opened wraps are
            # droped ensuring each pair (value, wrap) is tried at most once
            if plaintext is None:
                closed.append((epoch, w))
                continue
            # Because wrap glues the payload keys end to end before encrypting, once the
            # wrap is opened, we can split it by KEY_LEN to get the payload keys
            derived += (
                plaintext[i : i + KEY_LEN] for i in range(0, len(plaintext), KEY_LEN)
            )
        wraps = closed

        # DH: if value is a child's secret, combine it with the sibling's blinded key
        if siblings and len(value) == secret_len:
            # Convert the key's bytes to int to do the DH math
            x = key_to_int(value)
            # Get the blinded key constructed by alpha^x mod p, then for each of its
            # siblings, compute the parent's secret. Each member's blinded key is
            # alpha^x mod p
            for bk in siblings.get(pow(dh.alpha, x, dh.p), ()):
                # bk is the sibling's blinded key (alpha^y mod p). We compute the
                # parent's secret as (alpha^y)^x mod p
                derived.append(int_to_key(pow(bk, x, dh.p), secret_len))

        for new in derived:
            if new not in found:
                found.add(new)
                # Add it to the todo list as well in case it may be used to open other
                # wraps
                todo.append(new)
    return frozenset(found)


def can_read(keys: Iterable[bytes], data: DataMessage) -> bool:
    """Determines whether any of the keys can open the data's blob.

    Each key is tried as it is (Star/LKH group key) and through derive_group_key(),
    an HMAC-based derivation (TGDH root secret)."""
    return any(
        # Attempts with both keys to open the data blob
        open_sealed(key, data.blob, data.epoch) is not None
        for value in keys
        for key in (value, derive_group_key(key_to_int(value)))
    )


# ---------- checks ----------


def check_state(scheme: RekeyScheme, record: EpochRecord) -> list[Violation]:
    """Compares the scheme's current members and their group keys with the record.

    Reports MEMBERSHIP for anyone only one of the two lists as a member, and AGREEMENT
    for any recorded member without the recorded group ref and key. Reads the scheme's
    present state, so it must run right after the record's batch."""
    violations: list[Violation] = []

    # record.members is the ground truth, scheme.members() is what the scheme thinks it
    # has. This applies a violation for every member that is in one but not the other.
    for member in sorted(record.members ^ scheme.members()):
        detail = (
            "missing from the scheme"  # in record but not in scheme
            if member in record.members
            else "in the scheme but not in the group"  # in scheme but not in record
        )
        violations.append(Violation(Check.MEMBERSHIP, record.epoch, member, detail))

    # Every member of the group must hold the current group key
    # We loop over the record as scheme may have a bug
    expected = (record.group_ref, record.group_key)
    for member in sorted(record.members):
        # compare what the member believes to be the group key with the actual one.
        # This key comes from the scheme, so if the controller failed to change the key
        # and everyone agrees on the old one, this check will pass.
        held = scheme.member_group_key(member)
        if held == expected:
            continue
        if held is None:
            detail = "has no group key"
        elif held[0] != record.group_ref:
            detail = f"has {held[0]}, expected {record.group_ref}"
        else:
            detail = f"has the wrong key for {record.group_ref}"
        violations.append(Violation(Check.AGREEMENT, record.epoch, member, detail))

    return violations


def check_key_reuse(
    rings: Sequence[KeyRing], epochs: Sequence[EpochRecord]
) -> list[Violation]:
    """Finds keys and refs that are used more than once.

    Reports KEY_REUSE for a ref held with two different values, a value held under two
    different refs, and a group key shared by two epochs. Several members holding the
    same ref and value is normal."""
    violations: list[Violation] = []

    # Each distinct (ref, value) pair anyone has held, and when it first appeared
    # Many members hold the same pair, so we are collapsing them to keep only one pair
    # with the earliest epoch
    first_seen: dict[tuple[KeyRef, bytes], Epoch] = {}
    for ring in rings:
        for held in ring.history:
            pair = (held.ref, held.key)
            first_seen[pair] = min(held.epoch, first_seen.get(pair, held.epoch))

    # Go from oldest to newest, so the later use is the one reported
    value_of: dict[KeyRef, bytes] = {}
    ref_of: dict[bytes, KeyRef] = {}
    # Change the order (pair, e) -> (e, pair) to sort by epoch
    for epoch, (ref, key) in sorted((e, pair) for pair, e in first_seen.items()):
        # setdefault always returns the value stored and only saves the value once. Any
        # subsequent call with the same key will return the same value and NOT update
        # the saved value.
        if value_of.setdefault(ref, key) != key:  # different key, same ref
            detail = f"{ref} has more than one value"
            violations.append(Violation(Check.KEY_REUSE, epoch, None, detail))
        original = ref_of.setdefault(key, ref)
        if original != ref:  # different ref, same key
            detail = f"{ref} has the same value as {original}"
            violations.append(Violation(Check.KEY_REUSE, epoch, None, detail))

    # Every epoch needs its own group key. Compared only among the records, because a
    # TGDH ring holds the root secret while the record holds the key derived from it
    epoch_of: dict[bytes, Epoch] = {}
    for record in epochs:
        earlier = epoch_of.setdefault(record.group_key, record.epoch)
        if earlier != record.epoch:
            detail = f"same group key as epoch {earlier}"
            violations.append(Violation(Check.KEY_REUSE, record.epoch, None, detail))

    return violations


def check_secrecy(
    rings: Sequence[KeyRing],
    transcript: Transcript,
    epochs: Sequence[EpochRecord],
    dh: DHParams,
) -> list[Violation]:
    """Checks which epochs each person can read, using all the keys they ever held and
    the whole transcript.

    Reports SECRECY for an epoch someone can read without having been a member, and
    REACHABILITY for an epoch a member cannot read. Raises ValueError unless each epoch
    has exactly one probe message."""
    probes = {data.epoch: data for data in transcript.data}
    if len(probes) != len(transcript.data):
        raise ValueError("more than one probe message for an epoch")
    missing = [record.epoch for record in epochs if record.epoch not in probes]
    if missing:
        raise ValueError(f"no probe message for epochs {missing}")

    violations: list[Violation] = []
    for ring in sorted(rings, key=lambda r: r.member):
        # history and not ever_held(), which keeps only the last value of each ref
        # A faulty scheme could use the same ref for different values and make a leak go
        # unnoticed
        known = (held.key for held in ring.history)
        # Everything this person could ever compute. Using all their keys and the whole
        # transcript covers reading after leaving, reading before joining, and old keys
        # becoming useful after a rejoin
        keys = closure(known, transcript, dh)

        # can read | was a member | result
        # =========|==============|========================
        # yes      | yes          | fine
        # no       | no           | fine
        # yes      | no           | SECRECY violation
        # no       | yes          | REACHABILITY violation
        for record in epochs:
            was_member = ring.member in record.members
            if can_read(keys, probes[record.epoch]) == was_member:
                continue
            if was_member:
                check, detail = Check.REACHABILITY, "cannot read as a member"
            else:
                check, detail = Check.SECRECY, "can read as a non-member"
            violations.append(Violation(check, record.epoch, ring.member, detail))

    return violations


# ---------- running them during a simulation ----------


class Verifier:
    """Observes a simulation, runs the checks on it and collects the violations."""

    def __init__(self, *, secrecy_every_event: bool = True) -> None:
        self.secrecy_every_event = secrecy_every_event
        self.violations: set[Violation] = set()  # a repeated finding is kept once

    def after_apply(
        self,
        scheme: RekeyScheme,
        outcome: RekeyOutcome,
        transcript: Transcript,
        epochs: Sequence[EpochRecord],
    ) -> None:
        """Checks the state left by the batch just applied and, if secrecy_every_event
        is set, the whole history too. Adds any violations to self.violations."""
        self.violations.update(check_state(scheme, epochs[-1]))
        if self.secrecy_every_event:
            self.check_history(scheme, transcript, epochs)

    def check_history(
        self,
        scheme: RekeyScheme,
        transcript: Transcript,
        epochs: Sequence[EpochRecord],
    ) -> None:
        """Checks key reuse and secrecy over all epochs so far, for everyone who has
        ever been a member. Adds any violations to self.violations."""
        # Taken from the records and not from the scheme, which could have lost someone
        people = sorted({m for record in epochs for m in record.members})
        rings = [scheme.keyring(m) for m in people]
        dh = scheme.config.dh
        self.violations.update(check_key_reuse(rings, epochs))
        self.violations.update(check_secrecy(rings, transcript, epochs, dh))
