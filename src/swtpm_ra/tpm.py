"""
 tpm.py - SwtpmRA: the simulated TPM facade tying all modules together.

 SwtpmRA owns a TPMConfig, a StateStore and a CommandBackend and exposes
 both high-level Python methods and a raw TPM2-style frame handler
 (handle_frame). Every state-changing command bumps a persisted monotonic
 command counter and can be flushed to the state store, which makes
 save/restore and host-to-host migration produce identical quotes.
"""

import os
import shutil
import threading

from .backend import backend_from_uri
from .codec import (
    CC_MIGRATE,
    CC_STATE_LOAD,
    CC_STATE_SAVE,
    TPM2_CC_FLUSH_CONTEXT,
    TPM2_CC_GET_CAPABILITY,
    TPM2_CC_PCR_EXTEND,
    TPM2_CC_PCR_READ,
    TPM2_CC_PCR_RESET,
    TPM2_CC_QUOTE,
    TPM2_CC_SHUTDOWN,
    TPM2_CC_STARTUP,
    TPM_RC_BAD_TAG,
    TPM_RC_DISABLED,
    TPM_RC_FAILURE,
    TPM_RC_HANDLE,
    TPM_RC_SUCCESS,
    TPM_RC_VALUE,
    TPM_ST_NO_SESSIONS,
    TPM_SU_CLEAR,
    TPM_SU_STATE,
    CodecError,
    Packer,
    Unpacker,
    decode_request,
    decode_response,
    encode_request,
    encode_response,
)
from .pcr import PCRError, PCRPolicy
from .quote import QuoteError, quote as build_quote, verify_quote
from .state import (
    FileStateStore,
    PERMANENT_NAME,
    META_NAME,
    StateError,
    TPMState,
    state_store_from_uri,
)

CAP_PCR_BANKS = 1
CAP_PCR_COUNT = 2
CAP_RESETTABLE_PCRS = 3
CAP_PROFILE = 4
CAP_CLOCK = 5


class TPMCommandError(Exception):
    """Raised by high-level methods on a non-success TPM response code."""

    def __init__(self, message, response_code=TPM_RC_FAILURE):
        super().__init__(message)
        self.response_code = response_code


class TPMNotStartedError(TPMCommandError):
    """Raised when a command is issued before TPM2_Startup."""

    def __init__(self, message="TPM has not received TPM2_Startup"):
        super().__init__(message, TPM_RC_DISABLED)


class SwtpmRA:
    """A remote-attestation oriented software TPM."""

    def __init__(self, config, state_store=None, backend=None):
        self.config = config
        if config.encrypted_state and not config.state_key:
            raise StateError("encrypted_state requires a state_key")
        self.state_store = state_store or state_store_from_uri(
            config.state_uri, key=config.state_key
        )
        self.state = TPMState(config)
        self.backend = backend or backend_from_uri(config.backend_uri, tpm=self)
        self._lock = threading.RLock()
        if isinstance(self.state_store, FileStateStore):
            self.state_store.write_meta(config)

    # ---- lifecycle ----------------------------------------------------

    def startup(self, startup_type=TPM_SU_CLEAR):
        """Process TPM2_Startup, restoring persisted state when available."""
        if self.state.started:
            raise TPMCommandError("TPM is already started", TPM_RC_BAD_TAG)
        if self.state_store.exists():
            restored = self.state_store.load_permanent(self.config)
            restore_volatile = (
                startup_type == TPM_SU_STATE
                and self.state_store.load_volatile() is not None
            )
            if restore_volatile:
                self.state = restored
            else:
                # TPM_SU_CLEAR keeps the hierarchy/counters but resets PCRs.
                restored.pcr_policy = PCRPolicy.from_config(self.config)
                self.state = restored
        else:
            self.state.ensure_initialized()
            self.state_store.save_permanent(self.state)
        self.state.started = True
        self._persist_volatile()
        return self

    def shutdown(self, shutdown_type=TPM_SU_CLEAR):
        """Process TPM2_Shutdown and flush state."""
        self._require_started()
        self.state.command_count += 1
        self.state.clock += 1
        self.state.started = False
        self.state_store.save_permanent(self.state)
        if shutdown_type == TPM_SU_STATE:
            self._persist_volatile()
        else:
            self.state_store.clear_volatile()

    def save_state(self):
        """Persist permanent and volatile state without shutting down."""
        self._require_started()
        self.state_store.save_permanent(self.state)
        self._persist_volatile()

    def load_state(self):
        """Reload permanent state from the backing store."""
        if not self.state_store.exists():
            raise StateError("no persisted state to load")
        self.state = self.state_store.load_permanent(self.config)
        self.state.started = True
        self._persist_volatile()

    def migrate(self, target_state_uri=None, target_backend_uri=None):
        """Hand the TPM over to a fresh instance.

 The current permanent state is flushed and, when the target store is
 a different directory, copied there. The returned SwtpmRA performs
 TPM2_Startup(TPM_SU_STATE) so its PCRs, keys and counters match.
"""
        self._require_started()
        self.save_state()

        if target_state_uri is not None:
            target_config = self.config.with_state(target_state_uri)
            self._copy_state_tree(target_state_uri)
        else:
            target_config = self.config
        if target_backend_uri is not None:
            target_config = target_config.with_state(
                target_config.state_uri, backend_uri=target_backend_uri
            )

        migrated = SwtpmRA(target_config)
        migrated.load_state()
        return migrated

    # ---- PCR operations ----------------------------------------------

    def pcr_extend(self, index, data, algorithms=None):
        self._require_started()
        self.state.pcr_policy.extend(index, data, algorithms)
        self.state.command_count += 1

    def pcr_read(self, algorithm, index):
        self._require_started()
        return self.state.pcr_policy.read(algorithm, index)

    def pcr_reset(self, index, algorithms=None):
        self._require_started()
        self.state.pcr_policy.reset(index, algorithms)
        self.state.command_count += 1

    def pcr_snapshot(self):
        self._require_started()
        return self.state.pcr_policy.snapshot()

    # ---- attestation --------------------------------------------------

    def quote(self, nonce):
        self._require_started()
        signed = build_quote(
            self.state.keys,
            nonce,
            self.state.pcr_policy,
            clock=self.state.clock,
        )
        self.state.command_count += 1
        return signed

    def verify_quote(self, signed_quote, expected_nonce=None):
        return verify_quote(
            signed_quote,
            expected_nonce=expected_nonce,
            expected_composite=self.state.pcr_policy.snapshot(),
        )

    def get_capability(self, capability):
        self._require_started()
        packer = Packer()
        packer.u32(capability)
        if capability == CAP_PCR_BANKS:
            packer.u32(len(self.config.banks))
            for algorithm in self.config.banks:
                packer.u16(algorithm)
        elif capability == CAP_PCR_COUNT:
            packer.u32(self.config.pcr_count)
        elif capability == CAP_RESETTABLE_PCRS:
            packer.u32(len(self.config.resettable_pcrs))
            for index in self.config.resettable_pcrs:
                packer.u32(index)
        elif capability == CAP_PROFILE:
            packer.data(self.config.name.encode("utf-8"))
        elif capability == CAP_CLOCK:
            packer.u64(self.state.clock)
            packer.u64(self.state.command_count)
        else:
            raise TPMCommandError(
                "unknown capability %d" % capability, TPM_RC_VALUE
            )
        return packer.build()

    # ---- frame dispatch ----------------------------------------------

    def send_command(self, frame):
        """Send through the configured (possibly remote) backend."""
        return self.backend.send_command(frame)

    def handle_frame(self, frame):
        """Dispatch one raw TPM2 command frame to a response frame."""
        with self._lock:
            try:
                tag, command_code, parameters = decode_request(frame)
                if tag != TPM_ST_NO_SESSIONS:
                    raise TPMCommandError(
                        "unsupported session tag", TPM_RC_BAD_TAG
                    )
                response_parameters = self._dispatch(command_code, parameters)
                return encode_response(TPM_RC_SUCCESS, response_parameters)
            except TPMCommandError as exc:
                return encode_response(
                    exc.response_code, str(exc).encode("utf-8")
                )
            except PCRError as exc:
                return encode_response(
                    exc.response_code, str(exc).encode("utf-8")
                )
            except QuoteError as exc:
                return encode_response(
                    exc.response_code, str(exc).encode("utf-8")
                )
            except (CodecError, StateError, ValueError) as exc:
                return encode_response(
                    TPM_RC_VALUE, str(exc).encode("utf-8")
                )

    def _dispatch(self, command_code, parameters):
        unpacker = Unpacker(parameters)
        if command_code == TPM2_CC_STARTUP:
            startup_type = unpacker.u16()
            unpacker.end()
            self.startup(startup_type)
            return b""
        if command_code == TPM2_CC_SHUTDOWN:
            shutdown_type = unpacker.u16()
            unpacker.end()
            self.shutdown(shutdown_type)
            return b""
        if command_code == TPM2_CC_PCR_EXTEND:
            index = unpacker.u32()
            count = unpacker.u32()
            pairs = []
            for _ in range(count):
                algorithm = unpacker.u16()
                pairs.append((algorithm, unpacker.data()))
            unpacker.end()
            if not pairs:
                raise TPMCommandError("PCR_Extend needs at least one bank",
                                       TPM_RC_VALUE)
            for algorithm, data in pairs:
                self.pcr_extend(index, data, (algorithm,))
            return b""
        if command_code == TPM2_CC_PCR_READ:
            algorithm = unpacker.u16()
            index = unpacker.u32()
            unpacker.end()
            digest = self.pcr_read(algorithm, index)
            return Packer().u16(algorithm).u32(index).data(digest).build()
        if command_code == TPM2_CC_PCR_RESET:
            index = unpacker.u32()
            unpacker.end()
            self.pcr_reset(index)
            return b""
        if command_code == TPM2_CC_QUOTE:
            nonce = unpacker.data()
            unpacker.end()
            signed = self.quote(nonce)
            return (
                Packer()
                .data(signed.attest.encode())
                .data(signed.signature)
                .data(signed.ak_public)
                .u16(signed.algorithm)
                .build()
            )
        if command_code == TPM2_CC_GET_CAPABILITY:
            capability = unpacker.u32()
            unpacker.end()
            return self.get_capability(capability)
        if command_code == CC_STATE_SAVE:
            unpacker.end()
            self.save_state()
            return b""
        if command_code == CC_STATE_LOAD:
            unpacker.end()
            self.load_state()
            return b""
        if command_code == CC_MIGRATE:
            target = unpacker.data().decode("utf-8") or None
            unpacker.end()
            migrated = self.migrate(target_state_uri=target)
            migrated.backend.close()
            return Packer().data(migrated.config.name.encode("utf-8")).build()
        if command_code == TPM2_CC_FLUSH_CONTEXT:
            unpacker.u32()
            unpacker.end()
            self._require_started()
            return b""
        raise TPMCommandError(
            "unknown command code 0x%x" % command_code, TPM_RC_HANDLE
        )

    # ---- frame-level convenience wrappers ----------------------------

    def call(self, command_code, parameters=b""):
        """Send a frame through the backend and check the response."""
        response = self.send_command(encode_request(command_code, parameters))
        response_code, payload = decode_response(response)
        if response_code != TPM_RC_SUCCESS:
            raise TPMCommandError(
                "command 0x%x failed: %s"
                % (command_code, payload.decode("utf-8", "replace")),
                response_code,
            )
        return payload

    def close(self):
        self.backend.close()

    # ---- internals ----------------------------------------------------

    def _tick(self):
        self.state.command_count += 1

    def _persist_volatile(self):
        self.state_store.save_volatile(self.state)

    def _require_started(self):
        if not self.state.started:
            raise TPMNotStartedError()

    def _copy_state_tree(self, target_state_uri):
        source = self.state_store
        target = state_store_from_uri(target_state_uri, key=self.config.state_key)
        if not isinstance(source, FileStateStore) or not isinstance(
            target, FileStateStore
        ):
            return
        for name in (PERMANENT_NAME, META_NAME):
            source_path = os.path.join(source.directory, name)
            try:
                shutil.copy2(
                    source_path, os.path.join(target.directory, name)
                )
            except FileNotFoundError:
                pass


# Re-exported for callers that only import tpm.
__all__ = [
    "SwtpmRA",
    "TPMCommandError",
    "TPMNotStartedError",
    "CAP_PCR_BANKS",
    "CAP_PCR_COUNT",
    "CAP_RESETTABLE_PCRS",
    "CAP_PROFILE",
    "CAP_CLOCK",
]
