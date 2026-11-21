"""
 codec.py - TPM2-style command/response framing.

 Every request and response shares the 10 byte TPM2 header layout:

   request : tag(2) | commandSize(4) | commandCode(4) | parameters...
   response: tag(2) | responseSize(4) | responseCode(4) | parameters...

 The remaining payload uses length-prefixed fields (u16/u32 size followed
 by the raw bytes) so that every blob is canonical and self-describing.
"""

import struct

# TPM2_ST tags
TPM_ST_NO_SESSIONS = 0x8001
TPM_ST_SESSIONS = 0x8002

# TPM2_RC style response codes; the 0x100 bit marks TPM_RC format-one codes.
TPM_RC_SUCCESS = 0x000
TPM_RC_BAD_TAG = 0x01E
TPM_RC_VALUE = 0x100 + 0x004
TPM_RC_HANDLE = 0x100 + 0x00B
TPM_RC_PCR = 0x100 + 0x027
TPM_RC_POLICY = 0x100 + 0x02E
TPM_RC_FAILURE = 0x101
TPM_RC_DISABLED = 0x120
TPM_RC_RETRY = 0x922

# TPM2_CC command codes. Standard codes mirror the values used by the TPM
# 2.0 specification; management commands use the reserved 0x20000000 range.
TPM2_CC_STARTUP = 0x00000144
TPM2_CC_SHUTDOWN = 0x00000145
TPM2_CC_PCR_EXTEND = 0x00000182
TPM2_CC_PCR_READ = 0x0000017E
TPM2_CC_PCR_RESET = 0x0000013D
TPM2_CC_QUOTE = 0x00000158
TPM2_CC_GET_CAPABILITY = 0x0000017A
TPM2_CC_FLUSH_CONTEXT = 0x00000165
CC_STATE_SAVE = 0x20000001
CC_STATE_LOAD = 0x20000002
CC_MIGRATE = 0x20000003

# TPM2_SU startup/shutdown types
TPM_SU_CLEAR = 0x0000
TPM_SU_STATE = 0x0001

# TPM2_ALG_ID values from the TCG algorithm registry.
TPM_ALG_SHA1 = 0x0004
TPM_ALG_SHA256 = 0x000B
TPM_ALG_SHA384 = 0x000C
TPM_ALG_SHA512 = 0x000D
TPM_ALG_ED25519 = 0x0027

ALG_DIGEST_SIZE = {
    TPM_ALG_SHA1: 20,
    TPM_ALG_SHA256: 32,
    TPM_ALG_SHA384: 48,
    TPM_ALG_SHA512: 64,
}

ALG_NAME = {
    TPM_ALG_SHA1: "sha1",
    TPM_ALG_SHA256: "sha256",
    TPM_ALG_SHA384: "sha384",
    TPM_ALG_SHA512: "sha512",
}

NAME_TO_ALG = {name: alg for alg, name in ALG_NAME.items()}


class CodecError(ValueError):
    """Raised when a frame cannot be parsed."""


class Packer:
    """Accumulates canonical TPM-style parameter bytes."""

    def __init__(self):
        self._buf = bytearray()

    def u16(self, value):
        if not 0 <= value <= 0xFFFF:
            raise CodecError("u16 out of range: %d" % value)
        self._buf += struct.pack(">H", value)
        return self

    def u32(self, value):
        if not 0 <= value <= 0xFFFFFFFF:
            raise CodecError("u32 out of range: %d" % value)
        self._buf += struct.pack(">I", value)
        return self

    def u64(self, value):
        if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
            raise CodecError("u64 out of range: %d" % value)
        self._buf += struct.pack(">Q", value)
        return self

    def data(self, blob):
        if blob is None:
            blob = b""
        if not isinstance(blob, (bytes, bytearray)):
            raise CodecError("data payload must be bytes")
        self.u16(len(blob))
        self._buf += blob
        return self

    def build(self):
        return bytes(self._buf)


class Unpacker:
    """Parses canonical TPM-style parameter bytes with bounds checking."""

    def __init__(self, blob):
        self._buf = bytes(blob)
        self._pos = 0

    def remaining(self):
        return len(self._buf) - self._pos

    def u16(self):
        self._need(2)
        (value,) = struct.unpack_from(">H", self._buf, self._pos)
        self._pos += 2
        return value

    def u32(self):
        self._need(4)
        (value,) = struct.unpack_from(">I", self._buf, self._pos)
        self._pos += 4
        return value

    def u64(self):
        self._need(8)
        (value,) = struct.unpack_from(">Q", self._buf, self._pos)
        self._pos += 8
        return value

    def data(self):
        size = self.u16()
        self._need(size)
        blob = self._buf[self._pos:self._pos + size]
        self._pos += size
        return blob

    def end(self):
        if self._pos != len(self._buf):
            raise CodecError(
                "trailing bytes in frame: %d" % (len(self._buf) - self._pos)
            )

    def _need(self, size):
        if self._pos + size > len(self._buf):
            raise CodecError("frame truncated, need %d bytes" % size)


def encode_request(command_code, parameters=b"", tag=TPM_ST_NO_SESSIONS):
    """Wrap parameter bytes into a TPM2 command frame."""
    size = 10 + len(parameters)
    if size > 0xFFFFFFFF:
        raise CodecError("command frame too large")
    return struct.pack(">HII", tag, size, command_code) + parameters

def decode_request(frame):
    """Return (tag, command_code, parameters) from a TPM2 command frame."""
    if len(frame) < 10:
        raise CodecError("command frame shorter than header")
    tag, size, command_code = struct.unpack_from(">HII", frame, 0)
    if size != len(frame):
        raise CodecError(
            "command size mismatch: header=%d actual=%d" % (size, len(frame))
        )
    return tag, command_code, bytes(frame[10:])

def encode_response(response_code, parameters=b"", tag=TPM_ST_NO_SESSIONS):
    """Wrap parameter bytes into a TPM2 response frame."""
    size = 10 + len(parameters)
    return struct.pack(">HII", tag, size, response_code) + parameters

def decode_response(frame):
    """Return (response_code, parameters) from a TPM2 response frame."""
    if len(frame) < 10:
        raise CodecError("response frame shorter than header")
    tag, size, response_code = struct.unpack_from(">HII", frame, 0)
    if size != len(frame):
        raise CodecError(
            "response size mismatch: header=%d actual=%d" % (size, len(frame))
        )
    return response_code, bytes(frame[10:])
