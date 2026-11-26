import itertools
from abc import ABC, abstractmethod
from collections.abc import (
    Callable,
    Sequence,
)
from dataclasses import dataclass, replace
from importlib import import_module
from typing import ClassVar

from scalable_group_rekeying.costs import CostCounter
from scalable_group_rekeying.crypto import (
    KEY_LEN,
    KeySource,
    message_bytes,
    sign,
    unwrap,
    verify,
    wrap,
    wrap_context,
)
from scalable_group_rekeying.crypto import public_key as derive_public_key
from scalable_group_rekeying.types import (
    Batch,
    Epoch,
    Event,
    EventCost,
    EventKind,
    Fault,
    KeyRef,
    KeyRing,
    MemberId,
    RekeyMessage,
    SchemeConfig,
    Snapshot,
    Wrap,
)


@dataclass(frozen=True, slots=True)
class RekeyOutcome:
    epoch: Epoch
    batch: Batch
    messages: tuple[
        RekeyMessage, ...
    ]  # in send order. TGDH join: [joiner BK, sponsor tree update]
    cost: EventCost


@dataclass(frozen=True, slots=True)
class DeliveryResult:
    accepted: bool  # member changed its state because of the message
    learned: tuple[KeyRef, ...]  # keys it newly acquired


class RekeyScheme(ABC):
    name: ClassVar[str]  # "star" | "lkh" | "tgdh"
    supports_batch: ClassVar[bool] = False
    supported_faults: ClassVar[frozenset[Fault]] = frozenset({Fault.NONE})

    def __init__(self, config: SchemeConfig) -> None:
        if config.fault not in self.supported_faults:
            raise ValueError(f"{self.name} does not support fault {config.fault}")

        self.config = config
        self.keys = KeySource(config.seed)  # randomness source
        self.counter = CostCounter()
        self.epoch = Epoch(-1)
        self._rings: dict[MemberId, KeyRing] = {}  # never pruned
        self._signing_keys: dict[
            MemberId | None, bytes
        ] = {}  # per sender (None = controller), never pruned
        self._public_keys: dict[MemberId | None, bytes] = {}  # filled on demand
        self._new_signing_key(None)  # the controller's
        self._pow_cache: dict[
            tuple[int, int, int], int
        ] = {}  # stores the exponentiation results when cache is True
        self._next_seq = 0
        # uses id() as key, which identifies a particular object in memory. We don't use
        # the signature as the key would accept an altered message that copied a valid
        # signature, and using the whole message would mean processing all its wraps
        # on every lookup. IDs will differ even if the content is the same
        self._verified: dict[int, tuple[RekeyMessage, bool]] = {}
        self._node_ids = itertools.count()  # iterator of the nodes (start=0 step=1)

    # ---- lifecycle ----
    def init(self, members: Sequence[MemberId]) -> RekeyOutcome:
        """Creates the initial group (epoch 0) as a batch with one JOIN per member."""
        if self.epoch >= 0:
            raise RuntimeError("init() was already called")
        events = tuple(Event(i, EventKind.JOIN, m) for i, m in enumerate(members))
        batch = Batch(events, t_apply=0.0)
        self._validate(batch)
        return self._run(batch, self._init)

    @abstractmethod
    def _init(self, batch: Batch) -> Sequence[RekeyMessage]:
        """Scheme-specific setup of the initial group (epoch 0).

        batch has one JOIN per member, even if supports_batch is False. Their key
        rings and signing keys already exist.

        Must:
        - build the key structure, using self.keys for randomness and
          self._next_node() for node ids
        - store each member's own starting secret (individual key, or TGDH exponent)
          with self.keyring(m).learn(ref, secret, self.epoch)
        - send the rest in messages signed with self._signed()
        - pass those messages to the members through self.deliver() before returning,
          so member-side work is counted in this batch's cost
        - TGDH: tell members who is in the group first. A member that computes keys
          itself records them and marks the epoch completed
        - leave members(), group_key() and height() matching the new group

        Returns the messages in send order."""

    def _validate(self, batch: Batch) -> None:
        """Checks that the batch is valid for the current state. Raises ValueError if
        not."""
        if any(e.time > batch.t_apply for e in batch.events):
            raise ValueError("an event happens after the batch is applied")
        if not batch.events:
            raise ValueError("empty batch")
        ids = [e.member for e in batch.events]
        if len(set(ids)) != len(ids):
            raise ValueError("a member appears twice in the batch")
        current = self.members()
        for e in batch.events:
            match e.kind:
                case EventKind.JOIN:
                    ok = e.member >= 1 and e.member not in self._rings
                case EventKind.LEAVE:
                    ok = e.member in current
                case EventKind.REJOIN:
                    ok = e.member in self._rings and e.member not in current
            if not ok:
                raise ValueError(f"invalid {e.kind} for member {e.member}")
        leaving = {e.member for e in batch.events if e.kind == EventKind.LEAVE}
        if current and current <= leaving:  # skips during init() when current is empty
            raise ValueError("at least one current member must remain")

    def apply(self, batch: Batch) -> RekeyOutcome:
        """Applies a batch of events (JOIN, LEAVE, REJOIN) to the current group state.
        Returns the messages that were sent and the cost of this batch."""
        if self.epoch < 0:
            raise RuntimeError("init() must be called before apply()")
        if len(batch.events) > 1 and not self.supports_batch:
            raise ValueError(f"{self.name} does not support batches")
        self._validate(batch)
        return self._run(batch, self._apply)

    @abstractmethod
    def _apply(self, batch: Batch) -> Sequence[RekeyMessage]:
        """Scheme-specific rekey. self.epoch is already the new epoch.

        batch is already validated. It has one event if supports_batch is False,
        otherwise it can mix joins, leaves and rejoins.

        Must (unless self.config.fault deliberately breaks a rule):
        - replace every key a leaver knew and every key a joiner is about to learn
        - encrypt a new key only under keys whose holders are all entitled to it
        - Star/LKH: take new keys from self.keys, never deriving them from old
          ones. TGDH: take new shares from self.keys.exponent(); node keys follow
          by DH
        - in a batch, replace each affected key once, children before parents
        - bump KeyRef.version when a node's key changes; new nodes use
          self._next_node()
        - give a joiner or rejoiner a new leaf and a new starting secret, stored
          with self.keyring(m).learn(ref, secret, self.epoch); nothing from an
          earlier stint may become useful again
        - use self._wrap() and self._modexp(), so the work is counted
        - sign with self._signed() and deliver with self.deliver() before returning
        - TGDH: tell members the event first. The sponsor refreshes its share,
          records its new keys, marks the epoch completed and sends blinded keys
          (the whole tree on a join)

        Don't catch errors: carrying on would leave the group half updated.

        Returns the messages in send order."""

    def _run(
        self, batch: Batch, step: Callable[[Batch], Sequence[RekeyMessage]]
    ) -> RekeyOutcome:
        """Bookkeeping for init() and apply(): updates the epoch, calls the
        scheme-specific step, and returns the messages and cost."""
        members_before = len(self.members())
        self.counter = CostCounter()  # nothing carries over from earlier calls
        # After an object is destroyed, Python could give its id to a new one, which
        # would now inherit the cached verification result. Clear on every batch
        self._verified.clear()
        self.epoch = Epoch(self.epoch + 1)
        for e in batch.events:  # a rejoining member keeps their old ring
            if e.member not in self._rings:
                self._rings[e.member] = KeyRing(e.member)
                self._new_signing_key(e.member)
        messages = tuple(step(batch))  # the scheme's _init or _apply
        last_seq = max(e.seq for e in batch.events)
        self._next_seq = max(self._next_seq, last_seq + 1)
        cost = self.counter.finish(
            epoch=self.epoch,
            batch=batch,
            members_before=members_before,
            height=self.height(),
            messages=messages,
        )
        return RekeyOutcome(self.epoch, batch, messages, cost)

    # ---- events ----
    def join(self, m: MemberId) -> RekeyOutcome:
        """Rekeys for one new member."""
        return self._apply_single(EventKind.JOIN, m)

    def leave(self, m: MemberId) -> RekeyOutcome:
        """Rekeys for one member leaving."""
        return self._apply_single(EventKind.LEAVE, m)

    def rejoin(self, m: MemberId) -> RekeyOutcome:
        """Rekeys for one former member coming back."""
        return self._apply_single(EventKind.REJOIN, m)

    def _apply_single(self, kind: EventKind, m: MemberId) -> RekeyOutcome:
        """Wraps one event in a batch and applies it."""
        event = Event(self._next_seq, kind, m)
        return self.apply(Batch.single(event))

    # ---- global view for the simulator/verifier oracle, NOT the adversary ----
    @abstractmethod
    def members(self) -> frozenset[MemberId]:
        """Current members according to the scheme's own key structure.

        Empty before init(). Returns a copy, not a live view. The verifier compares
        it with the membership replayed from the events."""

    @abstractmethod
    def group_key(self) -> tuple[KeyRef, bytes]:
        """Ref and KEY_LEN-byte key of the real current group key, not one member's
        view. Only valid after init().

        Star/LKH: the root key. TGDH: the root's ref and derive_group_key() of the
        root secret."""

    def keyring(self, m: MemberId) -> KeyRing:
        """Current and former members. Raises if m never joined"""
        # Only a wrong id, a request for a nonexistent member or a call before init
        # could produce a KeyError. For all other members that have joined, as it's
        # never pruned it should always return something.
        return self._rings[m]

    @abstractmethod
    def height(self) -> int:
        """Edges from the root to the deepest leaf after the latest batch. Star is
        always 1; a tree that is a single leaf is 0."""

    # ---- signing keys ----
    def _new_signing_key(self, owner: MemberId | None) -> None:
        """Creates a signing key and caches it. The public key is derived on demand."""
        self._signing_keys[owner] = self.keys.signing_key()

    def public_key(self, sender: MemberId | None) -> bytes | None:
        """Gets the public signing key for a member and caches it. None if the sender
        has no signing key"""
        public = self._public_keys.get(sender)
        if (
            public is None and sender in self._signing_keys
        ):  # no public key yet but private key exists
            public = derive_public_key(self._signing_keys[sender])
            self._public_keys[sender] = public
        return public

    def signing_key(self, member: MemberId) -> bytes | None:
        """Gets the private signing key for a member. Outside the scheme, only a
        security game playing the `member` may call this."""
        return self._signing_keys.get(member)

    # ---- attack surface ----
    @abstractmethod
    def deliver(self, member: MemberId, msg: RekeyMessage) -> DeliveryResult:
        """Processes msg as member would, using only what that member has: its key
        ring, the public state it has stored, public signing keys and membership
        events, which are public. Never reads the controller's keys or another
        member's secrets.

        msg may be forged, replayed or meant for someone else, and member may have
        left. Reject it if:
        - recipient is another member
        - the sender may not send it (Star/LKH: only the controller, None; TGDH: a
          current member in this member's view, or the joiner)
        - msg.epoch is not newer than the last epoch this member completed, that
          is, got the group key for
        - self._signature_ok(msg) is False

        A rejected message changes nothing and returns DeliveryResult(False, ()).
        Never raises for a bad message.

        Otherwise opens each wrap it holds the key for with self._unwrap(w, key,
        msg.epoch), repeating until nothing new opens but never reopening one, or
        computes with self._modexp(). Records every key it learns or computes,
        path keys included, with self.keyring(member).learn(ref, key, msg.epoch).
        TGDH secrets use int_to_key() with the byte length of p.

        accepted: the member's state changed. learned: refs of the new keys, which
        can be empty (a TGDH member may only store blinded keys)."""

    @abstractmethod
    def member_group_key(self, member: MemberId) -> tuple[KeyRef, bytes] | None:
        """The group key member believes is current, from its own state only, in the
        same form as group_key(). None if it never got one. It can be stale or wrong,
        for example after the member leaves."""

    # ---- UI ----
    @abstractmethod
    def snapshot(self, viewer: MemberId | None = None) -> Snapshot:
        """The tree at the current epoch, for the UI. Read-only: changes no state and
        counts no costs.

        - nodes: every node, flat. Keys appear only as fingerprints (first 8 hex
          chars of SHA-256), never as bytes
        - changed: rekeyed by the last batch
        - held, on_copath: from viewer's point of view; False if viewer is None
        - bk_fp, on_copath, is_sponsor: TGDH only
        - wrap_edges: one per (wrapper, payload) pair in the last batch (Star/LKH)
        - last_event: caption such as "leave u7"
        - cost: leave None, as it is only known after the batch returns"""

    # ---- helpers shared by all schemes ----
    def _wrap(
        self, wrapper: KeyRef, wkey: bytes, payloads: Sequence[tuple[KeyRef, bytes]]
    ) -> Wrap:
        """Encrypts the payload keys, in order, under wkey for the current epoch."""
        if not payloads or any(len(key) != KEY_LEN for _, key in payloads):
            raise ValueError("a wrap needs one or more keys of KEY_LEN bytes")

        refs = tuple(ref for ref, _ in payloads)  # ((node, version), ...)
        plaintext = b"".join(key for _, key in payloads)
        context = wrap_context(wrapper, refs, self.epoch)
        blob = wrap(wkey, plaintext, context, self.keys.nonce())
        self.counter.add_wrap()
        return Wrap(wrapper, refs, blob)

    def _unwrap(self, w: Wrap, key: bytes, epoch: Epoch) -> tuple[bytes, ...] | None:
        """Returns the payload keys of w as a tuple, in the order of w.payloads"""
        context = wrap_context(w.wrapper, w.payloads, epoch)
        plaintext = unwrap(key, w.blob, context)
        if plaintext is None or len(plaintext) != len(w.payloads) * KEY_LEN:
            return None
        self.counter.add_unwrap()  # only successful decryptions are counted
        return tuple(
            plaintext[i : i + KEY_LEN] for i in range(0, len(plaintext), KEY_LEN)
        )

    def _modexp(self, actor: MemberId, base: int, e: int, p: int) -> int:
        self.counter.add_modexp(actor)  # counted even when the result is reused
        args = (base, e, p)
        if args in self._pow_cache:
            return self._pow_cache[args]
        result = pow(base, e, p)
        if self.config.cache:
            self._pow_cache[args] = result
        return result

    def _next_node(self) -> int:
        """Returns a new node id."""
        return next(self._node_ids)

    def _signed(self, msg: RekeyMessage) -> RekeyMessage:
        """Returns a copy of msg signed with its sender's key. If signing is off,
        returns msg unchanged."""
        if not self.config.sign:  # No signing
            return msg
        key = self._signing_keys[msg.sender]  # retrieve the sender's signing key
        return replace(
            msg, signature=sign(key, message_bytes(msg))
        )  # as the dataclass is frozen, we make a copy with the signature field updated

    def _signature_ok(self, msg: RekeyMessage) -> bool:
        """True if msg has a valid signature from its sender, or signing is off. It
        doesn't check whether that sender is allowed to send it (handled by deliver)."""
        if not self.config.sign:
            return True
        cached = self._verified.get(id(msg))
        if cached is not None:
            return cached[1]  # (id, (keyref, verified?))
        public = self.public_key(msg.sender)  # use public key for verification
        ok = public is not None and verify(public, message_bytes(msg), msg.signature)
        if self.config.cache:
            # storing msg keeps it alive, so no other object can get the same id
            self._verified[id(msg)] = (msg, ok)
        return ok


_SCHEMES = {  # name -> "module:class"
    "star": "scalable_group_rekeying.star:Star",
    "lkh": "scalable_group_rekeying.lkh:LKH",
    "tgdh": "scalable_group_rekeying.tgdh:TGDH",
}


def make_scheme(name: str, config: SchemeConfig | None = None) -> RekeyScheme:
    """Factory to create a scheme object by name.

    The scheme's module is imported only here, so a scheme that isn't written yet only
    fails when asked for.
    """
    if name not in _SCHEMES:
        raise ValueError(f"unknown scheme {name!r}, choose from {list(_SCHEMES)}")
    module_name, class_name = _SCHEMES[name].split(":")
    # import_module("scalable_group_rekeying.lkh") loads lkh.py
    # getattr(module, "LKH") gets the class
    scheme_class: type[RekeyScheme] = getattr(import_module(module_name), class_name)
    # scheme_class(...) creates the instance
    return scheme_class(config or SchemeConfig())  # use the provided config or defaults
