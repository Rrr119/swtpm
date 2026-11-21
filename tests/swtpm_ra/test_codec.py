"""Frame codec tests: canonical encoding, bounds and error handling."""

from _helpers import unittest

from swtpm_ra.codec import (
    CodecError,
    Packer,
    TPM2_CC_QUOTE,
    TPM_RC_SUCCESS,
    TPM_ST_NO_SESSIONS,
    Unpacker,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)


class CodecTest(unittest.TestCase):
    def test_request_roundtrip(self):
        parameters = Packer().u32(7).data(b"abc").build()
        frame = encode_request(TPM2_CC_QUOTE, parameters)
        tag, command, restored = decode_request(frame)
        self.assertEqual(tag, TPM_ST_NO_SESSIONS)
        self.assertEqual(command, TPM2_CC_QUOTE)
        unpacker = Unpacker(restored)
        self.assertEqual(unpacker.u32(), 7)
        self.assertEqual(unpacker.data(), b"abc")
        unpacker.end()

    def test_response_roundtrip(self):
        frame = encode_response(TPM_RC_SUCCESS, b"\x01\x02")
        code, payload = decode_response(frame)
        self.assertEqual(code, TPM_RC_SUCCESS)
        self.assertEqual(payload, b"\x01\x02")

    def test_size_mismatch_detected(self):
        frame = encode_request(TPM2_CC_QUOTE, b"")
        with self.assertRaises(CodecError):
            decode_request(frame[:-1])
        with self.assertRaises(CodecError):
            decode_response(frame + b"x")

    def test_truncated_frame_detected(self):
        with self.assertRaises(CodecError):
            decode_request(b"\x80\x01")

    def test_trailing_bytes_detected(self):
        parameters = Packer().u16(3).build()
        unpacker = Unpacker(parameters + b"\x00")
        self.assertEqual(unpacker.u16(), 3)
        with self.assertRaises(CodecError):
            unpacker.end()

    def test_u64_roundtrip(self):
        value = (1 << 64) - 17
        blob = Packer().u64(value).build()
        self.assertEqual(Unpacker(blob).u64(), value)

    def test_range_checks(self):
        with self.assertRaises(CodecError):
            Packer().u16(1 << 16)
        with self.assertRaises(CodecError):
            Packer().u32(-1)


if __name__ == "__main__":
    unittest.main()
