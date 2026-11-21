"""
 quote.py - deterministic remote-attestation quotes.

 The quote follows the TPM2_Quote structure closely: an attestation blob
 containing the caller nonce, the TPM clock/command counter and the PCR
 composite, signed by the persisted attestation key. All fields use the
 canonical length-prefixed encoding from codec.py and Ed25519 signing is
 deterministic, so two instances sharing the same state produce identical
 signatures for identical requests.
"""

import hashlib

from .codec import (
    TPM_ALG_ED25519,
    TPM_RC_VALUE,
    Packer,
    Unpacker,
)

# TPM2_GENERATED value used in the magic field of TPMS_ATTEST.
TPM_GENERATED = 0xFF544347

# Local TPM_ST_ATTEST_QUOTE tag.
TPM_ST_ATTEST_QUOTE = 0x8018


class QuoteError(Exception):
    """Raised when a quote cannot be created or verified."""

    def __init__(self, message, response_code=TPM_RC_VALUE):
        super().__init__(message)
        self.response_code = response_code


class AttestBlob:
    """Canonical, serializable contents of a signed quote."""

    def __init__(
        self,
        nonce,
        pcr_composite,
        clock=0,
        magic=TPM_GENERATED,
        type_tag=TPM_ST_ATTEST_QUOTE,
    ):
        self.magic = magic
        self.type_tag = type_tag
        self.nonce = bytes(nonce)
        self.clock = int(clock)
        # pcr_composite: {algorithm_id: concatenated PCR digest bytes}
        self.pcr_composite = dict(pcr_composite)

    def encode(self):
        packer = Packer()
        packer.u32(self.magic)
        packer.u16(self.type_tag)
        packer.u64(self.clock)
        packer.data(self.nonce)
        packer.u32(len(self.pcr_composite))
        for algorithm in sorted(self.pcr_composite):
            packer.u16(algorithm)
            packer.data(self.pcr_composite[algorithm])
        return packer.build()

    @classmethod
    def decode(cls, blob):
        unpacker = Unpacker(blob)
        magic = unpacker.u32()
        type_tag = unpacker.u16()
        clock = unpacker.u64()
        command_count = unpacker.u64()
        nonce = unpacker.data()
        count = unpacker.u32()
        composite = {}
        for _ in range(count):
            algorithm = unpacker.u16()
            composite[algorithm] = unpacker.data()
        unpacker.end()
        return cls(
            nonce=nonce,
            pcr_composite=composite,
            clock=clock,
            magic=magic,
            type_tag=type_tag,
        )

    def digest(self):
        """The value that is signed by the AK."""
        return hashlib.sha256(self.encode()).digest()

    def to_dict(self):
        return {
            "magic": self.magic,
            "type_tag": self.type_tag,
            "nonce": self.nonce.hex(),
            "clock": self.clock,
            "pcr_composite": {
                str(algorithm): digest.hex()
                for algorithm, digest in sorted(self.pcr_composite.items())
            },
        }


class Quote:
    """A complete quote: attestation blob, signature and AK public key."""

    def __init__(self, attest, signature, ak_public, algorithm=TPM_ALG_ED25519):
        self.attest = attest
        self.signature = bytes(signature)
        self.ak_public = bytes(ak_public)
        self.algorithm = algorithm

    def to_dict(self):
        data = self.attest.to_dict()
        data["signature_algorithm"] = self.algorithm
        data["signature"] = self.signature.hex()
        data["ak_public"] = self.ak_public.hex()
        return data

    def __eq__(self, other):
        if not isinstance(other, Quote):
            return NotImplemented
        return (
            self.attest.encode() == other.attest.encode()
            and self.signature == other.signature
            and self.ak_public == other.ak_public
            and self.algorithm == other.algorithm
        )


def quote(keys, nonce, pcr_policy, clock=0):
    """Build and sign a quote over the current PCR state."""
    nonce = bytes(nonce)
    if not 1 <= len(nonce) <= 64:
        raise QuoteError("quote nonce must be 1..64 bytes")
    attest = AttestBlob(
        nonce=nonce,
        pcr_composite=pcr_policy.snapshot(),
        clock=clock,
    )
    signature = keys.sign_quote(attest.encode())
    return Quote(attest, signature, keys.ak_public())


def verify_quote(signed_quote, expected_nonce=None, expected_composite=None):
    """Verify signature and optionally bind the quote to nonce/PCR state.

 Returns the decoded AttestBlob on success and raises QuoteError
 otherwise.
"""
    from cryptography.hazmat.primitives.asymmetric import ed25519

    if signed_quote.algorithm != TPM_ALG_ED25519:
        raise QuoteError(
            "unsupported signature algorithm 0x%x" % signed_quote.algorithm
        )
    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(
            signed_quote.ak_public
        )
        public_key.verify(signed_quote.signature, signed_quote.attest.encode())
    except Exception as exc:  # InvalidSignature and key parsing errors
        raise QuoteError("quote signature verification failed: %s" % exc) from exc

    if (
        expected_nonce is not None
        and signed_quote.attest.nonce != bytes(expected_nonce)
    ):
        raise QuoteError("quote nonce does not match the expected value")
    if (
        expected_composite is not None
        and signed_quote.attest.pcr_composite != dict(expected_composite)
    ):
        raise QuoteError("quote PCR composite does not match the expected state")
    return signed_quote.attest
