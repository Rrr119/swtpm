"""
 Configuration test 3/5: multi-bank attestation profile.

 SHA256, SHA384 and SHA512 banks are active simultaneously. A quote
 contains a composite for every bank and the composite survives restart
 and migration.
"""

import hashlib

from _helpers import (
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
    TPM_SU_STATE,
    SwtpmRATestCase,
)


class MultibankProfileTest(SwtpmRATestCase):
    preset_name = "multibank"

    def test_three_banks_are_enabled(self):
        tpm = self.make_tpm()
        self.assertEqual(
            self.capability_banks(tpm),
            [TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512],
        )

    def test_extend_touches_every_bank(self):
        tpm = self.make_tpm()
        data = b"multi-bank-event"
        tpm.pcr_extend(5, data)
        self.assertEqual(
            tpm.pcr_read(TPM_ALG_SHA256, 5),
            hashlib.sha256(b"\x00" * 32 + data).digest(),
        )
        self.assertEqual(
            tpm.pcr_read(TPM_ALG_SHA384, 5),
            hashlib.sha384(b"\x00" * 48 + data).digest(),
        )
        self.assertEqual(
            tpm.pcr_read(TPM_ALG_SHA512, 5),
            hashlib.sha512(b"\x00" * 64 + data).digest(),
        )

    def test_quote_composite_covers_all_banks(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(5, b"multi-bank-event")
        signed = tpm.quote(b"multi")
        self.assertEqual(
            set(signed.attest.pcr_composite),
            {TPM_ALG_SHA256, TPM_ALG_SHA384, TPM_ALG_SHA512},
        )
        tpm.verify_quote(signed, b"multi")

    def test_selective_bank_extend(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(1, b"only-384", algorithms=(TPM_ALG_SHA384,))
        self.assertEqual(
            tpm.pcr_read(TPM_ALG_SHA256, 1), b"\x00" * 32
        )
        self.assertNotEqual(
            tpm.pcr_read(TPM_ALG_SHA384, 1), b"\x00" * 48
        )

    def test_restart_preserves_all_composites(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(9, b"persisted-event")
        tpm.save_state()
        before = tpm.pcr_snapshot()
        reopened = self.reopen_tpm(tpm.config, TPM_SU_STATE)
        self.assertEqual(reopened.pcr_snapshot(), before)

    def test_migration_quote_byte_identical(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(0, b"firmware")
        tpm.pcr_extend(12, b"container-layer")
        self.assert_quote_migrates(tpm, tpm.config)


if __name__ == "__main__":
    import unittest

    unittest.main()
