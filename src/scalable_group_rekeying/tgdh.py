# @Chris

"""Tree-based Group Diffie-Hellman (TGDH), and the design decisions behind it.

KEYS
Each member holds one leaf with a secret share. A node with secret K has the blinded key
BK = alpha^K mod p, and a parent's secret is BK_sibling^(K_child) mod p. The group key
is derive_group_key() of the root secret.

MEMBERSHIP CHANGES
- Join and rejoin: the member gets a new leaf, paired with the shallowest, rightmost
  node where this doesn't make the tree taller, or else with the root. The new leaf is
  the right child of the new parent. The sponsor is the rightmost leaf under the left
  child.
- Leave: the leaver's sibling takes the parent's place. The sponsor is the rightmost
  leaf under that sibling.
- The sponsor draws a new share. Its leaf and every node above it get a new version.
  All other existing nodes, even in a promoted subtree, keep their refs.

MESSAGES
- Initial group: from left to right, each member sends one message with the nodes where
  it is the rightmost leaf.
- Join and rejoin: the joiner sends its leaf, then the sponsor sends the whole tree.
- Leave: the sponsor sends the nodes on its path.

PUBLISHED NODES (BlindedKey)
- A parent goes out with its child refs and a leaf with its member, so messages carry
  the structure of the tree.
- Every parent, including the root, must be published with its children. Without the
  root entry, closure can't derive the root secret from any secret below the root, so
  someone who still holds one goes unnoticed and the run looks clean.
- The root's bk is b"" (also when the root is a lone member's leaf), as nobody needs it.
  Receivers require it to be empty on the root and 1 < bk < p - 1 everywhere else, and
  never store the empty value.

WHAT MEMBERS ARE TOLD
Before any message, an internal announcement (not a RekeyMessage, and not new fields on
Event) tells members the epoch and:
- Initial members: the initial tree with its node ids.
- Existing members: the event, plus the new node ids on a join or rejoin.
- Joiner: its leaf id, the new parent id and the list of other members. The list comes
  from the public events, never from the message being checked.

ACCEPTING A MESSAGE
On top of the contract of RekeyScheme.deliver:
- The epoch must be the announced one.
- The sender must be the expected one: the sponsor, or the joiner for its own leaf. In
  the initial group, each node comes from the rightmost member under it.
- Initial and existing members: each entry (ref, children, member) must match their own
  tree.
- Joiner: the entries form one binary tree; the leaf owners are the listed members plus
  itself, each once; its leaf and parent have the given ids; its leaf is the right child
  and carries the bk it sent; and the sender is the rightmost leaf under its sibling.
- No received value, and no secret computed from it, is stored until the whole message
  passes. A rejected message changes nothing.
- A member completes an epoch only with both the root secret and the root's entry.

MEMBER STATE
- One private tree per member, with mutable nodes, parent links and a member-to-leaf
  map. No sharing between members is planned.
- Nodes hold no secrets. Those live only in the member's KeyRing, looked up by node.ref,
  so a new version hides the old secret by itself. A node's bk is cleared when its
  version changes. The sponsor reads its old share before the version changes.
- Once a message passes, nodes keep its KeyRef and bk objects, so members don't each
  hold an equal copy.
- Kept outside the tree: the last completed group key and epoch, and the member's last
  leaf ref, recorded when it leaves. Its tree is then dropped.

FAULTS
Supported: NONE, NO_SPONSOR_REFRESH and STALE_KEY_REUSE. WRAP_UNDER_DEPARTED and
SKIP_ANCESTOR are not.
- NO_SPONSOR_REFRESH: the sponsor keeps its old share. Versions still change as usual,
  so members accept and the verifier reports KEY_REUSE. A join followed by that member
  leaving brings back the earlier group key: test for that finding ("same group key as
  epoch N"), since the join alone already causes others.
- STALE_KEY_REUSE: a rejoiner reuses the last share it held (including one it refreshed
  as sponsor), and the sponsor still refreshes. Nothing leaks: test for KEY_REUSE after
  a leave and a rejoin.

THREAT MODEL AND EXPERIMENTS
- Members follow the protocol, and their signing keys and shares aren't stolen
  (experiment 7 leaks only a group key). Insiders are out of scope, as in the paper.
- An insider could fool a joiner under its own valid signature, so the victim in the
  forgery experiment (6) should be an existing member.
- Forgeries must arrive before the genuine message completes the victim: wrap
  scheme.deliver, and make each fake wrong only in the property being tested.
- Run TGDH with at most 1024 members. The member trees alone take about 250 MB there.
"""

from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

from scalable_group_rekeying.scheme import DeliveryResult, RekeyScheme
from scalable_group_rekeying.types import (
    Batch,
    Epoch,
    KeyRef,
    MemberId,
    RekeyMessage,
    Snapshot,
)


# eq=False so nodes are compared by identity and not their fields
@dataclass(slots=True, eq=False)
class _Node:
    """One node of a key tree. It holds only public values; a member's secret for it is
    in that member's KeyRing, under ref."""

    ref: KeyRef
    member: MemberId | None = None  # set on a leaf only
    parent: "_Node | None" = field(default=None, repr=False)
    left: "_Node | None" = field(default=None, repr=False)
    right: "_Node | None" = field(default=None, repr=False)
    height: int = 0  # edges down to the deepest leaf
    bk: bytes | None = None  # blinded key, once computed or received

    @property
    def rightmost(self) -> MemberId:
        """The member on the rightmost leaf under this node. This is how sponsors are
        picked"""
        node = self
        while node.right is not None:
            node = node.right
        assert node.member is not None
        return node.member


def _branch(ref: KeyRef, left: _Node, right: _Node) -> _Node:
    """Builds the node above left and right and links them to it."""
    height = 1 + max(left.height, right.height)
    node = _Node(ref, left=left, right=right, height=height)
    left.parent = right.parent = node
    return node


def _path(node: _Node) -> list[_Node]:
    """The node and every node above it, ending at the root."""
    path = [node]
    while (above := path[-1].parent) is not None:
        path.append(above)
    return path


def _sibling(node: _Node) -> _Node:
    """The other child of the node's parent. The root has no sibling."""
    parent = node.parent
    assert parent is not None
    other = parent.right if node is parent.left else parent.left
    assert other is not None
    return other


def _nodes(root: _Node) -> Iterator[_Node]:
    """Yields root and every node under it, parents first and left before right."""
    todo = [root]
    while todo:
        node = todo.pop()
        yield node  # hands out nodes one at a time so the caller can iterate over them
        if node.left is not None and node.right is not None:  # not a leaf
            todo += (node.right, node.left)


def _insertion_point(root: _Node) -> _Node:
    """The node a new leaf gets paired with: the shallowest, rightmost one where this
    doesn't make the tree taller, or else the root."""
    level, depth = [root], 0
    while level:
        for node in level:
            # Pair a node at depth with a new leaf reaches down to depth+node.height+1
            if depth + node.height < root.height:
                return node
        # the next level down, still ordered from right to left
        level = [c for n in level for c in (n.right, n.left) if c is not None]
        depth += 1
    # If every level is full, the new leaf pairs with the root, and the tree grows by 1
    return root


def _renew_path(leaf: _Node, created: _Node | None = None) -> None:
    """Walks from the sponsor's leaf to the root, updating heights, bumping versions and
    clearing blinded keys. The node a join has just created keeps its version."""
    for node in _path(leaf):
        if node.left is not None and node.right is not None:
            node.height = 1 + max(node.left.height, node.right.height)
        if node is not created:
            node.ref = KeyRef(node.ref.node, node.ref.version + 1)
            node.bk = None


@dataclass(slots=True)
class _Tree:
    """One copy of the key tree: its root, and where each member's leaf is."""

    root: _Node
    leaves: dict[MemberId, _Node]

    def add(self, member: MemberId, leaf_ref: KeyRef, parent_ref: KeyRef) -> MemberId:
        """Joins member next to the insertion point, renews the sponsor's path and
        returns the sponsor."""
        target = _insertion_point(self.root)  # decide where to put the new leaf
        above = target.parent  # read it now, as _branch overwrites it
        sponsor = (
            target.rightmost
        )  # select the sponsor as the rightmost leaf under the target insertion point
        self.leaves[member] = _Node(leaf_ref, member)
        created = _branch(
            parent_ref, target, self.leaves[member]
        )  # put old subtree on the left and joiner to the right
        self._replace(target, created, above)  # hangs the new branch where target was
        _renew_path(self.leaves[sponsor], created)  # update nodes in the sponsor's path
        return sponsor

    def remove(self, member: MemberId) -> MemberId:
        """Removes member, moves its sibling up into the parent's place, renews the
        sponsor's path and returns the sponsor."""
        leaf = self.leaves.pop(member)
        parent = leaf.parent
        assert parent is not None  # the last member can't leave
        sibling = _sibling(leaf)
        self._replace(
            parent, sibling, parent.parent
        )  # promote the sibling into the parent's place
        sponsor = sibling.rightmost
        _renew_path(self.leaves[sponsor])
        return sponsor

    def _replace(self, old: _Node, new: _Node, above: _Node | None) -> None:
        """Puts new where old was: under above, or at the root if above is None."""
        new.parent = above
        if above is None:
            self.root = new
        elif above.left is old:
            above.left = new
        else:
            above.right = new


@dataclass(frozen=True, slots=True)
class _Joining:
    """What a joiner is told about its place before it has the tree.

    When the sponsor's message arrives, the joiner checks that the leaf and parent have
    the given ids, that the leaf is the right child of the parent, and that the sender
    is the rightmost member under the joiner's sibling."""

    leaf: _Node  # its own leaf, whose bk it fills in when it publishes
    parent: KeyRef  # the new node that will sit above that leaf
    others: frozenset[MemberId]  # the members already in the group


@dataclass(slots=True)
class _Round:
    """What a member was told about one epoch, and the rekey progress through it. As
    rekey can take several messages, a member must remember which epoch it's waiting
    for, who may send, and whether the root's entry has arrived"""

    epoch: Epoch
    sponsor: MemberId | None = None  # None in the initial group and for a joiner
    joiner: MemberId | None = None  # who else is joining or rejoining, if anyone
    joining: _Joining | None = None  # set only for the joiner itself
    root_seen: bool = False  # True once the root's entry is accepted


@dataclass(slots=True)
class _MemberState:
    """What one member keeps between messages, apart from the secrets in its KeyRing."""

    current: _Round  # replaced at every announcement
    tree: _Tree | None = None  # None while joining and after leaving
    completed: Epoch = Epoch(
        -1
    )  # last epoch it got the group key for, starts at -1 meaning never
    group_key: tuple[KeyRef, bytes] | None = None  # the key from that epoch
    last_leaf: KeyRef | None = None  # its leaf ref when it last left

    @property
    def done(self) -> bool:
        """True once the member has the group key of the current epoch."""
        return self.completed == self.current.epoch


class TGDH(RekeyScheme):
    name = "tgdh"
    supports_batch = False

    def _init(self, batch: Batch) -> Sequence[RekeyMessage]:
        raise NotImplementedError

    def _apply(self, batch: Batch) -> Sequence[RekeyMessage]:
        raise NotImplementedError

    def members(self) -> frozenset[MemberId]:
        raise NotImplementedError

    def group_key(self) -> tuple[KeyRef, bytes]:
        raise NotImplementedError

    def height(self) -> int:
        raise NotImplementedError

    def deliver(self, member: MemberId, msg: RekeyMessage) -> DeliveryResult:
        raise NotImplementedError

    def member_group_key(self, member: MemberId) -> tuple[KeyRef, bytes] | None:
        raise NotImplementedError

    def snapshot(self, viewer: MemberId | None = None) -> Snapshot:
        raise NotImplementedError
