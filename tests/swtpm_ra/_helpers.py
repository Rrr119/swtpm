"""Shared helpers for the swtpm_ra configuration test-suite."""

import hashlib
import os
import sys
import tempfile
import threading
import unittest

SRC_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "src")
)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from swtpm_ra import (  # noqa: E402
    SocketCommandBackend,
    SocketCommandServer,
    SwtpmRA,
    get_preset,
)
from swtpm_ra.codec import (  # noqa: E402
    TPM2_CC_GET_CAPABILITY,
    TPM2_CC_PCR_EXTEND,
    TPM2_CC_QUOTE,
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
    TPM_RC_PCR,
    TPM_RC_SUCCESS,
    TPM_RC_VALUE,
    TPM_SU_CLEAR,
    TPM_SU_STATE,
    Packer,
    Unpacker,
    decode_response,
    encode_request,
)
from swtpm_ra.tpm import (  # noqa: E402
    CAP_PCR_BANKS,
    CAP_RESETTABLE_PCRS,
)

ALG_BY_NAME = {
    "sha1": TPM_ALG_SHA1,
    "sha256": TPM_ALG_SHA256,
    "sha384": TPM_ALG_SHA384,
    "sha512": TPM_ALG_SHA512,
}


class SwtpmRATestCase(unittest.TestCase):
    """Base class supplying a temp directory and TPM factory."""

    preset_name = "default"

    def setUp(self):
        self.tempdir = tempfile.mkdtemp(prefix="swtpm-ra-test-")

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tempdir, ignore_errors=True)

    def state_uri(self, name="state"):
        return "file://%s" % os.path.join(self.tempdir, name)

    def make_config(self, state_name="state", backend_uri=None):
        config = get_preset(self.preset_name)
        config = config.with_state(self.state_uri(state_name))
        if backend_uri is not None:
            config.backend_uri = backend_uri
        return config

    def make_tpm(self, state_name="state", start=True, backend=None):
        config = self.make_config(state_name)
        tpm = SwtpmRA(config, backend=backend)
        if start:
            tpm.startup(TPM_SU_CLEAR)
        return tpm

    def reopen_tpm(self, config, startup_type=TPM_SU_STATE):
        """Simulate a new process opening the same persisted state."""
        tpm = SwtpmRA(config)
        tpm.startup(startup_type)
        return tpm

    def extend_via_frame(self, tpm, index, algorithm, data):
        parameters = (
            Packer()
            .u32(index)
            .u32(1)
            .u16(algorithm)
            .data(data)
            .build()
        )
        response = tpm.send_command(
            encode_request(TPM2_CC_PCR_EXTEND, parameters)
        )
        code, _ = decode_response(response)
        self.assertEqual(code, TPM_RC_SUCCESS)

    def quote_via_frame(self, tpm, nonce):
        parameters = Packer().data(nonce).build()
        response = tpm.send_command(
            encode_request(TPM2_CC_QUOTE, parameters)
        )
        code, payload = decode_response(response)
        self.assertEqual(code, TPM_RC_SUCCESS)
        unpacker = Unpacker(payload)
        attest = unpacker.data()
        signature = unpacker.data()
        ak_public = unpacker.data()
        algorithm = unpacker.u16()
        unpacker.end()
        return attest, signature, ak_public, algorithm

    def capability_banks(self, tpm):
        payload = tpm.call(
            TPM2_CC_GET_CAPABILITY, Packer().u32(CAP_PCR_BANKS).build()
        )
        unpacker = Unpacker(payload)
        unpacker.u32()
        count = unpacker.u32()
        banks = [unpacker.u16() for _ in range(count)]
        unpacker.end()
        return banks

    def capability_resettable(self, tpm):
        payload = tpm.call(
            TPM2_CC_GET_CAPABILITY, Packer().u32(CAP_RESETTABLE_PCRS).build()
        )
        unpacker = Unpacker(payload)
        unpacker.u32()
        count = unpacker.u32()
        indices = [unpacker.u32() for _ in range(count)]
        unpacker.end()
        return indices

    def expected_extend_digest(self, algorithm_name, previous, data):
        return hashlib.new(algorithm_name, previous + data).digest()

    def assert_quote_migrates(self, tpm, config, nonce=b"migration-nonce"):
        """Quote before and after a state migration must be identical."""
        before = tpm.quote(nonce)
        target_uri = self.state_uri("migrated")
        migrated = tpm.migrate(target_state_uri=target_uri)
        after = migrated.quote(nonce)
        self.assertEqual(before, after)
        self.assertEqual(before.signature, after.signature)
        self.assertEqual(before.attest.encode(), after.attest.encode())
        migrated.verify_quote(after, expected_nonce=nonce)
        return migrated


class SocketBackendTestCase(SwtpmRATestCase):
    """Base class exercising commands through the UNIX socket backend."""

    def start_socket_server(self, config):
        socket_path = os.path.join(self.tempdir, "swtpm-ra.sock")
        config.backend_uri = "unix://%s" % socket_path
        server_tpm = SwtpmRA(config)
        server = SocketCommandServer(server_tpm, socket_path).start()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.stop)
        return socket_path, server_tpm

    def make_socket_client(self, config, socket_path):
        backend = SocketCommandBackend(socket_path, timeout=5.0)
        self.addCleanup(backend.close)
        return SwtpmRA(config, backend=backend)
