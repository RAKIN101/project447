"""secp256k1 ECC-ElGamal implementation written from scratch for CSE447.

ECC is the asymmetric algorithm assigned to post records. A plaintext chunk is
encoded as a curve point M. Encryption returns (kG, M + kQ); decryption computes
M = C2 - dC1. No symmetric encryption is used.
"""

import json
import secrets
from dataclasses import dataclass
from typing import Optional

_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_B = 7
_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
Point = Optional[tuple[int, int]]


def _add(first: Point, second: Point) -> Point:
    if first is None:
        return second
    if second is None:
        return first
    x1, y1 = first
    x2, y2 = second
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if first == second:
        slope = (3 * x1 * x1) * pow(2 * y1, -1, _P) % _P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    return x3, (slope * (x1 - x3) - y1) % _P


def _multiply(scalar: int, point: Point = _G) -> Point:
    result = None
    current = point
    while scalar:
        if scalar & 1:
            result = _add(result, current)
        current = _add(current, current)
        scalar >>= 1
    return result


def _serialize_point(point: Point) -> str:
    return "" if point is None else f"{point[0]:064x}:{point[1]:064x}"


def _deserialize_point(value: str) -> Point:
    if not value:
        return None
    x, y = value.split(":")
    return int(x, 16), int(y, 16)


@dataclass
class ECCPublicKey:
    point: str


@dataclass
class ECCPrivateKey:
    scalar: int


@dataclass
class ECCKeyPair:
    public: ECCPublicKey
    private: ECCPrivateKey


def generate_ecc_keypair() -> ECCKeyPair:
    scalar = secrets.randbelow(_N - 1) + 1
    return ECCKeyPair(ECCPublicKey(_serialize_point(_multiply(scalar))), ECCPrivateKey(scalar))


def _encode_message(message: bytes) -> Point:
    if len(message) > 28:
        raise ValueError("ECC message chunk is too long")
    payload = (len(message).to_bytes(2, "big") + message).ljust(30, b"\x00")
    base = int.from_bytes(payload, "big")
    for counter in range(256):
        x = (base << 8) | counter
        if x >= _P:
            break
        right_side = (pow(x, 3, _P) + _B) % _P
        y = pow(right_side, (_P + 1) // 4, _P)
        if pow(y, 2, _P) == right_side:
            return x, y
    raise ValueError("could not encode message as a curve point")


def _decode_message(point: Point) -> bytes:
    if point is None:
        raise ValueError("invalid ECC message point")
    payload = (point[0] >> 8).to_bytes(30, "big")
    length = int.from_bytes(payload[:2], "big")
    return payload[2 : 2 + length]


def ecc_encrypt(public: ECCPublicKey, message: bytes) -> str:
    """Encrypt bytes with ECC-ElGamal in 28-byte point-encoding chunks."""
    public_point = _deserialize_point(public.point)
    blocks = []
    for start in range(0, len(message), 28):
        message_point = _encode_message(message[start : start + 28])
        ephemeral = secrets.randbelow(_N - 1) + 1
        shared = _multiply(ephemeral, public_point)
        blocks.append({"c1": _serialize_point(_multiply(ephemeral)), "c2": _serialize_point(_add(message_point, shared))})
    return json.dumps(blocks, separators=(",", ":"))


def ecc_decrypt(private: ECCPrivateKey, ciphertext: str) -> bytes:
    """Recover bytes using M = C2 - dC1."""
    output = bytearray()
    for block in json.loads(ciphertext):
        c1 = _deserialize_point(block["c1"])
        c2 = _deserialize_point(block["c2"])
        shared = _multiply(private.scalar, c1)
        inverse_shared = (shared[0], (-shared[1]) % _P)
        output.extend(_decode_message(_add(c2, inverse_shared)))
    return bytes(output)
