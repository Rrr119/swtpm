"""
 Configuration test 5/5: remote command backend profile.

 Every command crosses the UNIX-domain socket backend. The test verifies
 remote startup/extend/quote, frame-level error propagation and quote
 parity between a socket client and a local instance on the same state,
 including after migration.
"""

import threading

from _helpers import (
    SocketBackendTestCase,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_RC_PCR,
    TPM_RC_SUCCESS,
    decode_response,
    encode_request,
)
from swtpm_ra import SwtpmRA
from swtpm_ra import SocketCommandServer
from swtpm_ra.codec import (
    TPM2_CC_PCR_EXTEND,
    TPM2_CC_PCR_RESET,
    TPM2_CC_STARTUP,
    Packer,
)


class SocketProfileTest(SocketBackendTestCase):
    preset_name = "socket"

    def setUp(self):
        super().setUp()
        self.config = self.make_config("socket-state")
        self.socket_path, self.server_tpm = self.start_socket_server(
            self.config
        )
        self.client = self.make_socket_client(self.config, self.socket_path)
        self.client.call(TPM2_CC_STARTUP, Packer().u16(0).build())

    def test_banks_visible_remotely(self):
        self.assertEqual(
            self.capability_banks(self.client),
            [TPM_ALG_SHA256, TPM_ALG_SHA384],
        )

    def test_full_remote_lifecycle(self):
        extend = (
            Packer()
            .u32(10)
            .u32(1)
            .u16(TPM_ALG_SHA256)
            .data(b"socket-event")
            .build()
        )
        code, _ = decode_response(
            self.client.send_command(
                encode_request(TPM2_CC_PCR_EXTEND, extend)
            )
        )
        self.assertEqual(code, TPM_RC_SUCCESS)

        attest, signature, ak_public, algorithm = self.quote_via_frame(
            self.client, b"socket-nonce"
        )
        self.assertEqual(len(signature), 64)
        self.assertEqual(len(ak_public), 32)

    def test_remote_error_is_propagated(self):
        frame = encode_request(
            TPM2_CC_PCR_RESET, Packer().u32(0).build()
        )
        code, _ = decode_response(self.client.send_command(frame))
        self.assertEqual(code, TPM_RC_PCR)

    def test_remote_and_local_quotes_match(self):
        self.extend_via_frame(
            self.client, 4, TPM_ALG_SHA256, b"shared-state-event"
        )
        attest_remote, sig_remote, _, _ = self.quote_via_frame(
            self.client, b"parity"
        )

        local = SwtpmRA(self.config)
        local.load_state()
        attest_local, sig_local, _, _ = self.quote_via_frame(
            local, b"parity"
        )
        self.assertEqual(attest_remote, attest_local)
        self.assertEqual(sig_remote, sig_local)

    def test_migration_quote_byte_identical(self):
        self.extend_via_frame(
            self.client, 0, TPM_ALG_SHA256, b"pre-migration"
        )
        before_attest, before_sig, _, _ = self.quote_via_frame(
            self.client, b"migration"
        )

        target_uri = self.state_uri("socket-migrated")
        migrated = self.server_tpm.migrate(
            target_state_uri=target_uri
        )
        after = migrated.quote(b"migration")
        self.assertEqual(after.attest.encode(), before_attest)
        self.assertEqual(after.signature, before_sig)

        # The migrated TPM can itself be reached through a new socket.
        new_socket = self.socket_path + ".2"
        server2 = SocketCommandServer(migrated, new_socket).start()
        thread = threading.Thread(
            target=server2.serve_forever, daemon=True
        )
        thread.start()
        self.addCleanup(server2.stop)

        client2 = self.make_socket_client(migrated.config, new_socket)
        attest2, sig2, _, _ = self.quote_via_frame(
            client2, b"migration"
        )
        self.assertEqual(attest2, before_attest)
        self.assertEqual(sig2, before_sig)

    def test_concurrent_clients_are_serialized(self):
        results = []
        errors = []

        def worker(worker_id):
            try:
                client = self.make_socket_client(
                    self.config, self.socket_path
                )
                self.extend_via_frame(
                    client,
                    20,
                    TPM_ALG_SHA256,
                    b"concurrent-%d" % worker_id,
                )
                results.append(worker_id)
            except Exception as exc:  # pragma: no cover - failure path
                errors.append(exc)

        threads = [
            threading.Thread(target=worker, args=(index,))
            for index in range(6)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        self.assertEqual(errors, [])
        self.assertEqual(len(results), 6)

        # After the barrier every client observes the same final state.
        final_quotes = set()
        for _ in range(3):
            client = self.make_socket_client(
                self.config, self.socket_path
            )
            attest, signature, _, _ = self.quote_via_frame(
                client, b"concurrent"
            )
            final_quotes.add((attest, signature))
        self.assertEqual(len(final_quotes), 1)


if __name__ == "__main__":
    import unittest

    unittest.main()
