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
        """Scheme-specific setup of the initial group: creates the keys and returns the
        messages, already signed, in send order."""

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
        """Scheme-specific rekey for self.epoch: updates the keys and returns the
        messages, already signed, in send order."""

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
    def members(self) -> frozenset[MemberId]: ...
    @abstractmethod
    def group_key(self) -> tuple[KeyRef, bytes]: ...
    def keyring(self, m: MemberId) -> KeyRing:
        """Current and former members. Raises if m never joined"""
        # Only a wrong id, a request for a nonexistent member or a call before init
        # could produce a KeyError. For all other members that have joined, as it's
        # never pruned it should always return something.
        return self._rings[m]

    @abstractmethod
    def height(self) -> int: ...  # Star = 1; LKH/TGDH = root->deepest leaf

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
    def deliver(self, member: MemberId, msg: RekeyMessage) -> DeliveryResult: ...
    @abstractmethod
    def member_group_key(
        self, member: MemberId
    ) -> tuple[KeyRef, bytes] | None: ...  # what THEY believe

    # ---- UI ----
    @abstractmethod
    def snapshot(self, viewer: MemberId | None = None) -> Snapshot: ...

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
