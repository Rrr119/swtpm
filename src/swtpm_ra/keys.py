"""
 keys.py - TPM key hierarchy simulation (EK + attestation key).

 Ed25519 is used instead of a randomized ECDSA scheme because it produces
 deterministic signatures: given the same persisted private key, nonce and
 PCR state every quote is byte-for-byte identical, including after the
 state has been migrated to another swtpm instance.
"""

import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from .codec import TPM_ALG_ED25519

KEY_SEED_LABEL = b"swtpm-ra-attestation-key-v1"


class KeyError(Exception):
    """Raised when key material cannot be created or restored."""


def _raw_private_key(key):
    return key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )


def _raw_public_key(key):
    return key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


class KeyHierarchy:
    """Endorsement key (EK) and attestation key (AK) of one simulated TPM."""

    algorithm = TPM_ALG_ED25519

    def __init__(self, ek=None, ak=None):
        self.ek = ek
        self.ak = ak

    @classmethod
    def generate(cls):
        return cls(
            ek=ed25519.Ed25519PrivateKey.generate(),
            ak=ed25519.Ed25519PrivateKey.generate(),
        )

    @classmethod
    def from_seed(cls, seed):
        """Derive both keys deterministically from a 32 byte seed.

        Derivation lets a fleet of simulated TPMs be rebuilt from a known
        seed while still exercising the same persistence/migration code
        paths.
        """
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            raise KeyError("key seed must be exactly 32 bytes")
        ek_material = hashlib.sha256(KEY_SEED_LABEL + b"|EK|" + bytes(seed)).digest()
        ak_material = hashlib.sha256(KEY_SEED_LABEL + b"|AK|" + bytes(seed)).digest()
        return cls(
            ek=ed25519.Ed25519PrivateKey.from_private_bytes(ek_material),
            ak=ed25519.Ed25519PrivateKey.from_private_bytes(ak_material),
        )

    def sign_quote(self, message):
        return self.ak.sign(message)

    def ak_public(self):
        return _raw_public_key(self.ak)

    def ek_public(self):
        return _raw_public_key(self.ek)

    def verify_quote(self, message, signature):
        self.ak.public_key().verify(signature, message)

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "ek": _raw_private_key(self.ek).hex(),
            "ak": _raw_private_key(self.ak).hex(),
        }

    @classmethod
    def from_dict(cls, data):
        if data.get("algorithm") != cls.algorithm:
            raise KeyError(
                "unsupported key algorithm: %r" % (data.get("algorithm"),)
            )
        return cls(
            ek=ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(data["ek"])
            ),
            ak=ed25519.Ed25519PrivateKey.from_private_bytes(
                bytes.fromhex(data["ak"])
            ),
        )
