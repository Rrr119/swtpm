"""
 Configuration test 1/5: TPM 2.0 factory-default profile.

 SHA1 + SHA256 banks, 24 PCRs, dynamic PCRs 16..23 resettable.
"""

import hashlib

from _helpers import (
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_RC_PCR,
    TPM_SU_CLEAR,
    TPM_SU_STATE,
    SwtpmRATestCase,
    decode_response,
    encode_request,
)
from swtpm_ra.codec import TPM2_CC_PCR_RESET, Packer


class DefaultProfileTest(SwtpmRATestCase):
    preset_name = "default"

    def test_banks_and_pcr_count(self):
        tpm = self.make_tpm()
        self.assertEqual(
            self.capability_banks(tpm), [TPM_ALG_SHA1, TPM_ALG_SHA256]
        )
        self.assertEqual(tpm.config.pcr_count, 24)
        self.assertEqual(
            self.capability_resettable(tpm), list(range(16, 24))
        )

    def test_extend_updates_both_banks(self):
        tpm = self.make_tpm()
        data = b"firmware-measurement"
        self.extend_via_frame(tpm, 0, TPM_ALG_SHA256, data)
        self.extend_via_frame(tpm, 0, TPM_ALG_SHA1, data)
        expected_sha256 = hashlib.sha256(
            b"\x00" * 32 + data
        ).digest()
        expected_sha1 = hashlib.sha1(b"\x00" * 20 + data).digest()
        self.assertEqual(tpm.pcr_read(TPM_ALG_SHA256, 0), expected_sha256)
        self.assertEqual(tpm.pcr_read(TPM_ALG_SHA1, 0), expected_sha1)

    def test_high_level_extend_updates_all_banks(self):
        tpm = self.make_tpm()
        data = b"firmware-measurement"
        tpm.pcr_extend(0, data)
        self.assertEqual(
            tpm.pcr_read(TPM_ALG_SHA256, 0),
            hashlib.sha256(b"\x00" * 32 + data).digest(),
        )
        self.assertEqual(
            tpm.pcr_read(TPM_ALG_SHA1, 0),
            hashlib.sha1(b"\x00" * 20 + data).digest(),
        )

    def test_static_pcr_cannot_reset(self):
        tpm = self.make_tpm()
        frame = encode_request(
            TPM2_CC_PCR_RESET, Packer().u32(0).build()
        )
        code, message = decode_response(tpm.handle_frame(frame))
        self.assertEqual(code, TPM_RC_PCR)
        self.assertIn("not resettable", message.decode())

    def test_dynamic_pcr_reset(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(16, b"event")
        self.assertNotEqual(tpm.pcr_read(TPM_ALG_SHA256, 16), b"\x00" * 32)
        tpm.pcr_reset(16)
        self.assertEqual(tpm.pcr_read(TPM_ALG_SHA256, 16), b"\x00" * 32)

    def test_persistence_and_restart_quote(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(4, b"boot-loader")
        tpm.save_state()
        quote_before = tpm.quote(b"nonce")

        reopened = self.reopen_tpm(tpm.config, TPM_SU_STATE)
        self.assertEqual(reopened.quote(b"nonce"), quote_before)

    def test_su_clear_keeps_key_resets_pcrs(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(2, b"event")
        ak = tpm.state.keys.ak_public()
        tpm.save_state()
        reopened = self.reopen_tpm(tpm.config, TPM_SU_CLEAR)
        self.assertEqual(reopened.state.keys.ak_public(), ak)
        self.assertEqual(reopened.pcr_read(TPM_ALG_SHA256, 2), b"\x00" * 32)

    def test_migration_quote_byte_identical(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(0, b"firmware")
        tpm.pcr_extend(10, b"kernel")
        self.assert_quote_migrates(tpm, tpm.config)


if __name__ == "__main__":
    import unittest

    unittest.main()
