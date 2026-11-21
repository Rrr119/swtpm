"""
 Configuration test 2/5: FIPS-hardened profile.

 SHA1 is disabled, only the SHA256 bank exists. An encrypted state store
 protects the persisted hierarchy and migration still yields an identical
 quote.
"""

import os

from _helpers import (
    SwtpmRA,
    TPM_ALG_SHA256,
    TPM_RC_VALUE,
    TPM_SU_STATE,
    SwtpmRATestCase,
    decode_response,
    encode_request,
)
from swtpm_ra import get_preset
from swtpm_ra.codec import TPM2_CC_PCR_EXTEND, Packer
from swtpm_ra.config import ConfigError
from swtpm_ra.state import StateError


class FipsProfileTest(SwtpmRATestCase):
    preset_name = "fips"

    def test_sha1_is_rejected(self):
        with self.assertRaises(ConfigError):
            get_preset("fips").__class__(
                name="bad", banks=("sha1", "sha256"), fips=True
            )

    def test_single_sha256_bank(self):
        tpm = self.make_tpm()
        self.assertEqual(self.capability_banks(tpm), [TPM_ALG_SHA256])
        self.assertTrue(tpm.config.fips)

    def test_extending_disabled_bank_fails(self):
        tpm = self.make_tpm()
        from _helpers import TPM_ALG_SHA1

        parameters = (
            Packer()
            .u32(0)
            .u32(1)
            .u16(TPM_ALG_SHA1)
            .data(b"event")
            .build()
        )
        code, _ = decode_response(
            tpm.handle_frame(
                encode_request(TPM2_CC_PCR_EXTEND, parameters)
            )
        )
        self.assertEqual(code, TPM_RC_VALUE)

    def _encrypted_config(self, state_name):
        config = self.make_config(state_name)
        config.encrypted_state = True
        config.state_key = b"fips-state-secret-key-0123456789"[:32]
        return config

    def test_encrypted_state_is_confidential(self):
        config = self._encrypted_config("enc")
        tpm = SwtpmRA(config)
        tpm.startup()
        tpm.pcr_extend(7, b"confidential-event")
        tpm.save_state()

        permanent = os.path.join(
            self.tempdir, "enc", "tpm-ra.permanent"
        )
        on_disk = open(permanent, "rb").read()
        self.assertNotIn(b"confidential-event", on_disk)

    def test_wrong_state_key_rejected(self):
        config = self._encrypted_config("enc")
        tpm = SwtpmRA(config)
        tpm.startup()
        tpm.save_state()

        wrong = self._encrypted_config("enc")
        wrong.state_key = b"x" * 32
        with self.assertRaises(StateError):
            SwtpmRA(wrong).startup(TPM_SU_STATE)

    def test_encrypted_migration_quote_identical(self):
        config = self._encrypted_config("enc")
        tpm = SwtpmRA(config)
        tpm.startup()
        tpm.pcr_extend(3, b"fips-boot")
        before = tpm.quote(b"fips-nonce")

        target = self._encrypted_config("enc-migrated")
        migrated = tpm.migrate(
            target_state_uri=target.state_uri
        )
        self.assertEqual(migrated.quote(b"fips-nonce"), before)


if __name__ == "__main__":
    import unittest

    unittest.main()
