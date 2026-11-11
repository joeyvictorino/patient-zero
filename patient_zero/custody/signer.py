"""Dependency-free RFC 8032 Ed25519 signatures.

Deterministic signing and seed-based key generation follow RFC 8032. Python big
integers are not constant-time: this is fine for verifying, and for signing on
a machine you control. For signing where an attacker can time the process, use
an audited hardware or OS key service. Private seeds never enter a seal.
"""
from __future__ import annotations

from hashlib import sha512, blake2b
import secrets

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = (-121665 * pow(121666, _P - 2, _P)) % _P
_I = pow(2, (_P - 1) // 4, _P)
_IDENTITY = (0, 1, 1, 0)


def _recover_x(y: int, sign_bit: int) -> int:
    xx = ((y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P:
        x = (x * _I) % _P
    if (x * x - xx) % _P or (x == 0 and sign_bit):
        raise ValueError("Invalid Ed25519 point")
    return x if x % 2 == sign_bit else _P - x


_BY = (4 * pow(5, _P - 2, _P)) % _P
_BX = _recover_x(_BY, 0)
_BASE = (_BX, _BY, 1, (_BX * _BY) % _P)


def _add(p: tuple[int, ...], q: tuple[int, ...]) -> tuple[int, ...]:
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = ((y1 - x1) * (y2 - x2)) % _P
    b = ((y1 + x1) * (y2 + x2)) % _P
    c = (2 * _D * t1 * t2) % _P
    d = (2 * z1 * z2) % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return ((e * f) % _P, (g * h) % _P, (f * g) % _P, (e * h) % _P)


def _multiply(point: tuple[int, ...], scalar: int) -> tuple[int, ...]:
    result = _IDENTITY
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


def _encode(point: tuple[int, ...]) -> bytes:
    x, y, z, _ = point
    inv_z = pow(z, _P - 2, _P)
    x, y = (x * inv_z) % _P, (y * inv_z) % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(encoded: bytes) -> tuple[int, ...]:
    if len(encoded) != 32:
        raise ValueError("Ed25519 point must have 32 bytes")
    n = int.from_bytes(encoded, "little")
    y, sign_bit = n & ((1 << 255) - 1), n >> 255
    if y >= _P:
        raise ValueError("Noncanonical Ed25519 encoding")
    x = _recover_x(y, sign_bit)
    return (x, y, 1, (x * y) % _P)


def _secret_scalar(seed: bytes) -> tuple[int, bytes]:
    digest = sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar = (scalar & ((1 << 254) - 8)) | (1 << 254)
    return scalar, digest[32:]


def generate_keypair(seed: bytes | None = None) -> tuple[str, str]:
    """Return (private seed hex, public key hex); explicit seeds are repeatable."""
    if seed is None:
        seed = secrets.token_bytes(32)
    if not isinstance(seed, bytes):
        raise TypeError("Signing seed must be bytes")
    if len(seed) != 32:
        seed = blake2b(b"PATIENT-ZERO-ED25519-SEED\x00" + seed, digest_size=32).digest()
    scalar, _ = _secret_scalar(seed)
    return seed.hex(), _encode(_multiply(_BASE, scalar)).hex()


def sign(payload: bytes, private_key: str) -> str:
    seed = bytes.fromhex(private_key)
    if len(seed) != 32:
        raise ValueError("Ed25519 private seed must have 32 bytes")
    scalar, prefix = _secret_scalar(seed)
    public = _encode(_multiply(_BASE, scalar))
    r = int.from_bytes(sha512(prefix + payload).digest(), "little") % _L
    r_encoded = _encode(_multiply(_BASE, r))
    challenge = int.from_bytes(sha512(r_encoded + public + payload).digest(), "little") % _L
    return (r_encoded + ((r + challenge * scalar) % _L).to_bytes(32, "little")).hex()


def verify(payload: bytes, signature: str, public_key: str) -> bool:
    """Strict prime-subgroup verification rejecting scalar/point malleability."""
    try:
        sig, pub = bytes.fromhex(signature), bytes.fromhex(public_key)
        if len(sig) != 64 or len(pub) != 32:
            return False
        s = int.from_bytes(sig[32:], "little")
        if s >= _L:
            return False
        a, r = _decode(pub), _decode(sig[:32])
        identity = _encode(_IDENTITY)
        if pub == identity or _encode(_multiply(a, _L)) != identity:
            return False
        if _encode(_multiply(r, _L)) != identity:
            return False
        challenge = int.from_bytes(sha512(sig[:32] + pub + payload).digest(), "little") % _L
        return secrets.compare_digest(_encode(_multiply(_BASE, s)),
                                      _encode(_add(r, _multiply(a, challenge))))
    except (ValueError, TypeError, OverflowError):
        return False
