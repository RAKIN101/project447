"""RSA-OAEP implementation written from scratch for CSE447.

RSA is the asymmetric algorithm assigned to user and profile records.
No RSA implementation from a cryptography library is used here.
"""

import base64
import hashlib
import hmac
import json
import math
import secrets
from dataclasses import dataclass


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


def _hash(value: bytes) -> bytes:
    return hashlib.sha256(value).digest()


def _mgf1(seed: bytes, length: int) -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < length:
        output.extend(hashlib.sha256(seed + counter.to_bytes(4, "big")).digest())
        counter += 1
    return bytes(output[:length])


def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    if b == 0:
        return a, 1, 0
    gcd, x, y = _extended_gcd(b, a % b)
    return gcd, y, x - (a // b) * y


def _inverse(value: int, modulus: int) -> int:
    gcd, x, _ = _extended_gcd(value, modulus)
    if gcd != 1:
        raise ValueError("modular inverse does not exist")
    return x % modulus


def _probably_prime(candidate: int, rounds: int = 24) -> bool:
    if candidate < 2 or candidate % 2 == 0:
        return candidate == 2
    for small in (3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if candidate == small:
            return True
        if candidate % small == 0:
            return False
    power, odd = 0, candidate - 1
    while odd % 2 == 0:
        power += 1
        odd //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, odd, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(power - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if _probably_prime(candidate):
            return candidate


@dataclass
class RSAPublicKey:
    n: int
    e: int


@dataclass
class RSAPrivateKey:
    n: int
    d: int
    e: int


@dataclass
class RSAKeyPair:
    public: RSAPublicKey
    private: RSAPrivateKey


def generate_rsa_keypair(bits: int = 1024) -> RSAKeyPair:
    """Generate an RSA keypair using generated primes and modular arithmetic."""
    if bits < 1024 or bits % 2:
        raise ValueError("RSA key size must be even and at least 1024 bits")
    exponent = 65537
    while True:
        first, second = _prime(bits // 2), _prime(bits // 2)
        if first == second:
            continue
        modulus = first * second
        totient = (first - 1) * (second - 1)
        if math.gcd(exponent, totient) == 1:
            break
    private_exponent = _inverse(exponent, totient)
    return RSAKeyPair(RSAPublicKey(modulus, exponent), RSAPrivateKey(modulus, private_exponent, exponent))


def _oaep_encode(message: bytes, block_size: int) -> bytes:
    hash_size = 32
    if len(message) > block_size - 2 * hash_size - 2:
        raise ValueError("RSA message chunk is too long")
    label_hash = _hash(b"")
    padding = label_hash + b"\x00" * (block_size - len(message) - 2 * hash_size - 2) + b"\x01" + message
    seed = secrets.token_bytes(hash_size)
    masked_data = bytes(a ^ b for a, b in zip(padding, _mgf1(seed, block_size - hash_size - 1)))
    masked_seed = bytes(a ^ b for a, b in zip(seed, _mgf1(masked_data, hash_size)))
    return b"\x00" + masked_seed + masked_data


def _oaep_decode(encoded: bytes) -> bytes:
    hash_size = 32
    if len(encoded) < 2 * hash_size + 2 or encoded[0] != 0:
        raise ValueError("invalid RSA OAEP block")
    masked_seed = encoded[1 : 1 + hash_size]
    masked_data = encoded[1 + hash_size :]
    seed = bytes(a ^ b for a, b in zip(masked_seed, _mgf1(masked_data, hash_size)))
    data = bytes(a ^ b for a, b in zip(masked_data, _mgf1(seed, len(masked_data))))
    if not hmac.compare_digest(data[:hash_size], _hash(b"")):
        raise ValueError("RSA OAEP label mismatch")
    separator = data.find(b"\x01", hash_size)
    if separator < 0 or any(data[hash_size:separator]):
        raise ValueError("invalid RSA OAEP padding")
    return data[separator + 1 :]


def rsa_encrypt(public: RSAPublicKey, message: bytes) -> str:
    """Encrypt bytes with RSA-OAEP, chunking long records into RSA blocks."""
    block_size = (public.n.bit_length() + 7) // 8
    chunk_size = block_size - 2 * 32 - 2
    blocks = []
    for start in range(0, len(message), chunk_size):
        encoded = _oaep_encode(message[start : start + chunk_size], block_size)
        number = pow(int.from_bytes(encoded, "big"), public.e, public.n)
        blocks.append(_encode(number.to_bytes(block_size, "big")))
    return json.dumps(blocks, separators=(",", ":"))


def rsa_decrypt(private: RSAPrivateKey, ciphertext: str) -> bytes:
    """Decrypt RSA-OAEP blocks with the private exponent."""
    block_size = (private.n.bit_length() + 7) // 8
    output = bytearray()
    for encoded_block in json.loads(ciphertext):
        number = int.from_bytes(_decode(encoded_block), "big")
        encoded = pow(number, private.d, private.n).to_bytes(block_size, "big")
        output.extend(_oaep_decode(encoded))
    return bytes(output)
