# TODO: I just defined the interface here, we need to implement each of the functions
# I wrote a small comment on each function to roughly explain what I planned it to do
# You may change them as you wish Zeyad
import random
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,  # noqa: F401 TODO: REMOVE this ignore
    Ed25519PublicKey,  # noqa: F401 TODO: REMOVE this ignore
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from scalable_group_rekeying.types import Epoch, KeyRef, RekeyMessage

KEY_LEN, NONCE_LEN, TAG_LEN = 32, 12, 16
SIG_KEY_LEN, SIG_LEN = 32, 64


class KeySource:
    """Defines the randomness of the project.

    When seed=none, uses the OS CSPRNG, otherwise uses a seeded PRNG for reproducible
    testing.
    """

    def __init__(self, seed: int | None = None) -> None:
        # Define the generators
        self._keys = self._stream(seed, "key")
        self._nonces = self._stream(seed, "nonce")
        self._signing_keys = self._stream(seed, "sign")
        self._exponents = self._stream(seed, "exponent")

    def key(self) -> bytes:
        """Fresh symmetric key"""
        return self._keys.randbytes(KEY_LEN)

    def nonce(self) -> bytes:
        """Fresh nonce for one wrap or sealed message. Should never be reused with the
        same key."""
        return self._nonces.randbytes(NONCE_LEN)

    def signing_key(self) -> bytes:
        """Fresh signing key"""
        return self._signing_keys.randbytes(SIG_KEY_LEN)

    def exponent(self, q: int) -> int:
        """TGDH private share, uniform in [2, q-1]"""

        # If exp is:
        # 0 -> BK = 1
        # 1 -> BK = alpha
        # >= q -> BK repeats 0, 1...
        return self._exponents.randrange(
            2, q
        )  # needs int in this range instead of fixed num of bytes

    @staticmethod  # <- Doesn't depend on the instance
    def _stream(seed: int | None, label: str) -> random.Random:
        if seed is None:
            return secrets.SystemRandom()
        return random.Random(f"{seed}:{label}")  # append label to avoid collision


# Wraps


def wrap_context(wrapper: KeyRef, payloads: tuple[KeyRef, ...], epoch: Epoch) -> bytes:
    """Binds a blob to its wrapper, payloads and epoch.

    This context is added to the tag so a valid blob that is sent with a different label
      or in a later epoch can be identified."""
    numbers = [epoch, wrapper.node, wrapper.version, len(payloads)]
    for ref in payloads:
        numbers += [ref.node, ref.version]
    return b"wrap" + b"".join(n.to_bytes(8, "big") for n in numbers)


def wrap(key: bytes, payload: bytes, context: bytes, nonce: bytes) -> bytes:
    """Encrypts payload with key and nonce.

    Returns nonce || ciphertext || tag"""
    # Ensure nonce length matches the expected length as AESGCM accepts any length of
    # nonce
    if len(nonce) != NONCE_LEN:
        raise ValueError("Invalid nonce length")

    # Add the nonce for uniqueness, making sure same payload with same key and context
    # produce different ciphertexts.
    return nonce + AESGCM(key).encrypt(nonce, payload, context)


def unwrap(key: bytes, blob: bytes, context: bytes) -> bytes | None:
    """Decrypts blob with key. Returns None if the tag is invalid, bad key or nonce
    length is incorrect.

    Returns the payload bytes"""
    nonce, body = blob[:NONCE_LEN], blob[NONCE_LEN:]  # nonce || ciphertext || tag
    try:
        return AESGCM(key).decrypt(nonce, body, context)
    except (InvalidTag, ValueError):  # bad tag, or bad key or nonce length
        return None


def wrap_len(
    n_payloads: int,
) -> int:
    """Returns the length of a wrap blob with n_payloads, given KEY_LEN, NONCE_LEN and
    TAG_LEN"""
    return NONCE_LEN + n_payloads * KEY_LEN + TAG_LEN  # nounce || ciphertext || tag


# The same primitives of wrap and unwrap, but for data messages under the epoch's group
# key
def seal(group_key: bytes, plaintext: bytes, epoch: Epoch, nonce: bytes) -> bytes: ...


def open_sealed(group_key: bytes, blob: bytes, epoch: Epoch) -> bytes | None: ...


# Converts between integers (for secrets) and bytes (for keyring)
def int_to_key(x: int, nbytes: int) -> bytes: ...  # TGDH exponent ↔ ring bytes
def key_to_int(b: bytes) -> int: ...
def derive_group_key(
    root_secret: int, label: bytes
) -> bytes: ...  # hash the DH value, never use it raw


# signatures (thin wrappers over cryptography's Ed25519)


def public_key(
    signing_key: bytes,
) -> bytes: ...  # signing_key = SIG_KEY_LEN bytes from KeySource.key()


def sign(signing_key: bytes, data: bytes) -> bytes: ...  # SIG_LEN bytes, deterministic


def verify(
    public_key: bytes, data: bytes, signature: bytes
) -> bool: ...  # False on ANY failure, never raises


def message_bytes(
    msg: RekeyMessage,
) -> bytes: ...  # what gets signed: every field except `signature`
