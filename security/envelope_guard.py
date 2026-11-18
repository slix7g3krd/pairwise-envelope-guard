"""Envelope encryption guard for database field-level encryption.

Design notes (defects fixed):
- KEK/DEK separation: callers supply a KEK; the DEK is derived from it
  via HKDF-SHA256 with a domain-separation label. The KEK itself never
  touches plaintext directly.
- Nonce uniqueness: derive_nonce(seed, counter) is deterministic per
  (seed, counter) but distinct across counters, so a monotonic counter
  (or random seed) guarantees nonce uniqueness per key.
- AAD binds tenant + field name, so ciphertexts cannot be replayed
  across tenants or columns.
- Every ciphertext record carries a key version so rotation stays
  decryptable.
- Decryption failure returns None and never falls back to plaintext.
- The GCM IV is derived from the per-message nonce (never a fixed
  constant); the message payload additionally carries a random salt so
  empty/NULL values encrypt to unpredictable ciphertext.
- The full 16-byte GCM tag is kept (hex-encoded as 32 chars), never
  truncated.
- Keys are never logged or interpolated into messages; records expose
  only ciphertext, tag, nonce and version.
"""

import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_GCM_TAG_LEN = 16          # bytes; full tag, never truncated
_IV_LEN = 12               # bytes; GCM standard IV size
_SALT_LEN = 16             # bytes; random per-message salt
_DEK_INFO = b"envelope-guard/dek/v1"
_NONCE_INFO = b"envelope-guard/nonce/v1"
_IV_INFO = b"envelope-guard/iv/v1"


def _to_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError("key/nonce material must be bytes or str")


def _hkdf(ikm, info, length):
    """Single-step HKDF (extract+expand) with SHA-256."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def _derive_dek(kek):
    """Derive the data-encryption key from the key-encryption key.

    KEK and DEK are never the same key: the DEK is an HKDF output bound
    to this module's domain-separation label.
    """
    return _hkdf(_to_bytes(kek), _DEK_INFO, 32)


def derive_nonce(seed, counter):
    """Deterministic, unique-per-counter nonce (hex string).

    Same (seed, counter) -> same nonce; different counter -> different
    nonce, so a counter can never silently reuse a nonce under one key.
    """
    msg = _to_bytes(seed) + b":" + str(counter).encode("ascii")
    return hmac.new(_NONCE_INFO, msg, hashlib.sha256).hexdigest()[: _IV_LEN * 2]


def aad(tenant, field):
    """Additional authenticated data binding tenant and field name.

    Length-prefixed so ('t1', 'email') and ('t1e', 'mail') cannot
    collide.
    """
    t = str(tenant).encode("utf-8")
    f = str(field).encode("utf-8")
    return f"{len(t)}:".encode("ascii") + t + f


def _derive_iv(nonce):
    """Map an arbitrary nonce string to a fixed-size GCM IV."""
    return _hkdf(_to_bytes(nonce), _IV_INFO, _IV_LEN)


def encrypt_field(plaintext, kek, nonce, aad_value, version=1):
    """Encrypt one field value under a DEK derived from the KEK.

    Returns a record dict with hex ciphertext, full hex tag, the nonce
    and the key version. A random salt is prepended to the plaintext so
    empty/NULL values produce unpredictable, non-empty ciphertext.
    """
    dek = _derive_dek(kek)
    iv = _derive_iv(nonce)
    salt = os.urandom(_SALT_LEN)
    payload = salt + _to_bytes(plaintext)
    ct_and_tag = AESGCM(dek).encrypt(iv, payload, _to_bytes(aad_value))
    cipher, tag = ct_and_tag[:-_GCM_TAG_LEN], ct_and_tag[-_GCM_TAG_LEN:]
    return {
        "cipher": cipher.hex(),
        "tag": tag.hex(),
        "nonce": nonce,
        "version": version,
    }


def decrypt_field(record, kek, aad_value):
    """Decrypt a record produced by encrypt_field.

    Returns the plaintext, or None on any failure (bad key, bad AAD,
    corrupted record). Never falls back to returning plaintext.
    """
    try:
        cipher = bytes.fromhex(record["cipher"])
        tag = bytes.fromhex(record["tag"])
        if len(tag) != _GCM_TAG_LEN:
            return None
        dek = _derive_dek(kek)
        iv = _derive_iv(record["nonce"])
        payload = AESGCM(dek).decrypt(iv, cipher + tag, _to_bytes(aad_value))
        return payload[_SALT_LEN:].decode("utf-8")
    except Exception:
        return None


def rotate_key(record):
    """Rotate a key record: bump the version and generate fresh key
    material, keeping the previous key available so old data can be
    re-encrypted (dual-write migration) before it is retired."""
    old_key = record["key"]
    new_key = os.urandom(32)
    return {
        "v": record["v"] + 1,
        "key": new_key,
        "previous": old_key,
    }
