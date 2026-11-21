"""
 Persistence tests: atomic state files, tamper detection, volatile state
 semantics and quote stability across restart and migration.
"""

import json
import os

from _helpers import (
    TPM_ALG_SHA256,
    TPM_SU_CLEAR,
    TPM_SU_STATE,
    SwtpmRATestCase,
)
from swtpm_ra import (
    FileStateStore,
    MemoryStateStore,
    SwtpmRA,
    get_preset,
)
from swtpm_ra.state import (
    PERMANENT_NAME,
    StateError,
    TPMState,
    state_store_from_uri,
)


class PersistenceTest(SwtpmRATestCase):
    preset_name = "default"

    def test_state_files_are_written(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(1, b"event")
        tpm.save_state()
        state_dir = os.path.join(self.tempdir, "state")
        names = set(os.listdir(state_dir))
        self.assertIn(PERMANENT_NAME, names)
        self.assertIn("tpm-ra.volatile", names)
        self.assertIn("tpm-ra.meta", names)

    def test_memory_store_roundtrip(self):
        config = get_preset("default")
        tpm = SwtpmRA(config, state_store=MemoryStateStore())
        tpm.startup()
        tpm.pcr_extend(2, b"mem-event")
        tpm.save_state()
        before = tpm.quote(b"mem")

        reopened = SwtpmRA(config, state_store=tpm.state_store)
        reopened.startup(TPM_SU_STATE)
        self.assertEqual(reopened.quote(b"mem"), before)

    def test_tampered_permanent_state_rejected(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(1, b"event")
        tpm.save_state()
        path = os.path.join(self.tempdir, "state", PERMANENT_NAME)
        with open(path, "rb") as handle:
            envelope = json.loads(handle.read())
        payload = bytearray(bytes.fromhex(envelope["payload"]))
        payload[-1] ^= 0xFF
        envelope["payload"] = bytes(payload).hex()
        with open(path, "wb") as handle:
            handle.write(json.dumps(envelope).encode())

        with self.assertRaises(StateError):
            self.reopen_tpm(tpm.config, TPM_SU_STATE)

    def test_missing_volatile_forces_clear_startup(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(1, b"event")
        tpm.save_state()
        ak = tpm.state.keys.ak_public()
        os.remove(
            os.path.join(self.tempdir, "state", "tpm-ra.volatile")
        )

        # TPM_SU_STATE with no volatile state falls back to CLEAR.
        reopened = self.reopen_tpm(tpm.config, TPM_SU_STATE)
        self.assertEqual(reopened.pcr_read(TPM_ALG_SHA256, 1), b"\x00" * 32)
        self.assertEqual(reopened.state.keys.ak_public(), ak)

    def test_shutdown_clear_removes_volatile_state(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(1, b"event")
        tpm.shutdown(TPM_SU_CLEAR)
        self.assertFalse(
            os.path.exists(
                os.path.join(self.tempdir, "state", "tpm-ra.volatile")
            )
        )
        reopened = self.reopen_tpm(tpm.config, TPM_SU_CLEAR)
        self.assertEqual(reopened.pcr_read(TPM_ALG_SHA256, 1), b"\x00" * 32)

    def test_shutdown_state_preserves_volatile_state(self):
        tpm = self.make_tpm()
        tpm.pcr_extend(1, b"event")
        digest = tpm.pcr_read(TPM_ALG_SHA256, 1)
        tpm.shutdown(TPM_SU_STATE)
        reopened = self.reopen_tpm(tpm.config, TPM_SU_STATE)
        self.assertEqual(reopened.pcr_read(TPM_ALG_SHA256, 1), digest)

    def test_state_store_uri_factory(self):
        store = state_store_from_uri("memory://")
        self.assertIsInstance(store, MemoryStateStore)
        store = state_store_from_uri(
            "file://%s/factory" % self.tempdir
        )
        self.assertIsInstance(store, FileStateStore)
        with self.assertRaises(StateError):
            state_store_from_uri("bogus://nowhere")

    def test_uninitialized_state_cannot_be_persisted(self):
        config = self.make_config("empty")
        state = TPMState(config)
        with self.assertRaises(StateError):
            state.to_permanent_dict()

    def test_migration_copies_full_state_tree(self):
        tpm = self.make_tpm("source")
        tpm.pcr_extend(0, b"migrate-me")
        before = tpm.quote(b"tree")
        target = self.state_uri("target")
        migrated = tpm.migrate(target_state_uri=target)
        self.assertEqual(migrated.quote(b"tree"), before)
        target_dir = os.path.join(self.tempdir, "target")
        self.assertIn(PERMANENT_NAME, os.listdir(target_dir))
        self.assertEqual(
            migrated.pcr_read(TPM_ALG_SHA256, 0),
            tpm.pcr_read(TPM_ALG_SHA256, 0),
        )


if __name__ == "__main__":
    import unittest

    unittest.main()
