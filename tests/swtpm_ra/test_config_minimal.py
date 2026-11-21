"""
 Configuration test 4/5: reduced embedded profile.

 Only 8 PCRs exist and none of them is resettable. Out-of-range indices
 are rejected and the profile still supports restart/migration quotes.
"""

from _helpers import (
    TPM_ALG_SHA256,
    TPM_RC_PCR,
    TPM_RC_SUCCESS,
    TPM_RC_VALUE,
    TPM_SU_STATE,
    SwtpmRATestCase,
    decode_response,
    encode_request,
)
from swtpm_ra.codec import (
    TPM2_CC_PCR_EXTEND,
    TPM2_CC_PCR_READ,
    TPM2_CC_PCR_RESET,
    Packer,
)


class MinimalProfileTest(SwtpmRATestCase):
    preset_name = "minimal"

    def test_reduced_pcr_count(self):
        tpm = self.make_tpm()
        self.assertEqual(tpm.config.pcr_count, 8)
        self.assertEqual(self.capability_resettable(tpm), [])

    def test_no_pcr_is_resettable(self):
        tpm = self.make_tpm()
        for index in range(8):
            frame = encode_request(
                TPM2_CC_PCR_RESET, Packer().u32(index).build()
            )
            code, _ = decode_response(tpm.handle_frame(frame))
            self.assertEqual(code, TPM_RC_PCR)

    def test_out_of_range_index_rejected(self):
        tpm = self.make_tpm()
        parameters = (
            Packer()
            .u32(8)
            .u32(1)
            .u16(TPM_ALG_SHA256)
            .data(b"event")
            .build()
        )
        code, _ = decode_response(
            tpm.handle_frame(
                encode_request(TPM2_CC_PCR_EXTEND, parameters)
            )
        )
        self.assertEqual(code, TPM_RC_VALUE)

    def test_frame_level_pcr_read(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(3, b"embedded-event")
        parameters = Packer().u16(TPM_ALG_SHA256).u32(3).build()
        code, payload = decode_response(
            tpm.handle_frame(
                encode_request(TPM2_CC_PCR_READ, parameters)
            )
        )
        self.assertEqual(code, TPM_RC_SUCCESS)
        from swtpm_ra.codec import Unpacker

        unpacker = Unpacker(payload)
        self.assertEqual(unpacker.u16(), TPM_ALG_SHA256)
        self.assertEqual(unpacker.u32(), 3)
        digest = unpacker.data()
        unpacker.end()
        self.assertEqual(digest, tpm.pcr_read(TPM_ALG_SHA256, 3))

    def test_migration_quote_byte_identical(self):
        tpm = self.make_tpm()
        for index in range(8):
            tpm.pcr_extend(index, b"event-%d" % index)
        self.assert_quote_migrates(tpm, tpm.config)

    def test_restart_quote_byte_identical(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(0, b"boot")
        tpm.save_state()
        before = tpm.quote(b"tiny-nonce")
        reopened = self.reopen_tpm(tpm.config, TPM_SU_STATE)
        self.assertEqual(reopened.quote(b"tiny-nonce"), before)


if __name__ == "__main__":
    import unittest

    unittest.main()
