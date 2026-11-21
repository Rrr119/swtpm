"""
 state.py - versioned, atomic TPM state persistence.

 The permanent state holds the key hierarchy, PCR policy, monotonic command
 counter and TPM clock and must survive process restarts and migration.
 The volatile state captures whether the TPM is currently started; after a
 crash (missing volatile state) the next TPM2_Startup runs with
 TPM_SU_CLEAR and the PCRs are reset.

 State files are written atomically (temp file + fsync + rename) and carry
 a version header plus an HMAC-SHA256 tag. When a key is supplied the
 payload is additionally sealed with AES-256/128-GCM.
"""

import hashlib
import hmac
import json
import os
import tempfile

from .keys import KeyHierarchy
from .pcr import PCRPolicy

STATE_VERSION = 1
PERMANENT_NAME = "tpm-ra.permanent"
VOLATILE_NAME = "tpm-ra.volatile"
META_NAME = "tpm-ra.meta"


class StateError(Exception):
    """Raised when state cannot be stored, loaded or authenticated."""


class TPMState:
    """All serializable contents of one simulated TPM."""

    def __init__(
        self,
        config,
        keys=None,
        pcr_policy=None,
        command_count=0,
        clock=0,
        started=False,
    ):
        self.config = config
        self.keys = keys
        self.pcr_policy = pcr_policy
        self.command_count = int(command_count)
        self.clock = int(clock)
        self.started = bool(started)

    def ensure_initialized(self):
        """Create the hierarchy and PCR banks on first TPM2_Startup."""
        if self.keys is None:
            self.keys = KeyHierarchy.generate()
        if self.pcr_policy is None:
            self.pcr_policy = PCRPolicy.from_config(self.config)

    def to_permanent_dict(self):
        if self.keys is None or self.pcr_policy is None:
            raise StateError("cannot persist an uninitialized TPM state")
        return {
            "version": STATE_VERSION,
            "profile": self.config.to_dict(),
            "keys": self.keys.to_dict(),
            "pcrs": self.pcr_policy.to_dict(),
            "command_count": self.command_count,
            "clock": self.clock,
        }

    @classmethod
    def from_permanent_dict(cls, data, config):
        if int(data.get("version", 0)) != STATE_VERSION:
            raise StateError(
                "unsupported state version: %r" % data.get("version")
            )
        restored_profile = data["profile"]
        if restored_profile["banks"] != list(config.bank_names()):
            raise StateError(
                "PCR bank mismatch: state=%r config=%r"
                % (restored_profile["banks"], list(config.bank_names()))
            )
        if restored_profile["pcr_count"] != config.pcr_count:
            raise StateError("PCR count mismatch between state and config")
        return cls(
            config=config,
            keys=KeyHierarchy.from_dict(data["keys"]),
            pcr_policy=PCRPolicy.from_dict(data["pcrs"]),
            command_count=data["command_count"],
            clock=data["clock"],
            started=False,
        )


class StateStore:
    """Abstract persistence backend."""

    def save_permanent(self, state):
        raise NotImplementedError

    def load_permanent(self, config):
        raise NotImplementedError

    def save_volatile(self, state):
        raise NotImplementedError

    def load_volatile(self):
        raise NotImplementedError

    def clear_volatile(self):
        raise NotImplementedError

    def exists(self):
        raise NotImplementedError


def _seal(payload, key):
    if key is None:
        return payload, None
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = os.urandom(12)
    ciphertext = AESGCM(_derive_aes_key(key)).encrypt(
        nonce, payload, b"swtpm-ra-state"
    )
    return nonce + ciphertext, "aes-gcm"


def _unseal(sealed, key, mode):
    if mode is None:
        if key is not None:
            raise StateError("encrypted state expected but plaintext was found")
        return sealed
    if mode != "aes-gcm" or key is None:
        raise StateError("unsupported or missing state encryption: %r" % mode)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce, ciphertext = sealed[:12], sealed[12:]
    return AESGCM(_derive_aes_key(key)).decrypt(
        nonce, ciphertext, b"swtpm-ra-state"
    )


def _derive_aes_key(key):
    return hashlib.sha256(b"swtpm-ra-aesgcm" + bytes(key)).digest()


def _hmac_tag(key, payload):
    return hmac.new(
        hashlib.sha256(b"swtpm-ra-hmac" + bytes(key)).digest(),
        payload,
        hashlib.sha256,
    ).digest()


class FileStateStore(StateStore):
    """Persist state as files inside a directory."""

    def __init__(self, directory, key=None):
        self.directory = os.path.abspath(str(directory))
        self.key = bytes(key) if key is not None else None
        os.makedirs(self.directory, exist_ok=True)

    def _path(self, name):
        return os.path.join(self.directory, name)

    def exists(self):
        return os.path.isfile(self._path(PERMANENT_NAME))

    def save_permanent(self, state):
        payload = json.dumps(
            state.to_permanent_dict(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        sealed, mode = _seal(payload, self.key)
        envelope = {
            "version": STATE_VERSION,
            "encryption": mode,
            "payload": sealed.hex(),
            "hmac": _hmac_tag(self.key or b"", sealed).hex(),
        }
        self._atomic_write(
            self._path(PERMANENT_NAME),
            json.dumps(envelope, sort_keys=True).encode("utf-8"),
        )

    def load_permanent(self, config):
        envelope = self._read_envelope(PERMANENT_NAME)
        sealed = bytes.fromhex(envelope["payload"])
        expected = bytes.fromhex(envelope["hmac"])
        if not hmac.compare_digest(
            _hmac_tag(self.key or b"", sealed), expected
        ):
            raise StateError("permanent state integrity check failed")
        payload = _unseal(sealed, self.key, envelope.get("encryption"))
        return TPMState.from_permanent_dict(json.loads(payload), config)

    def save_volatile(self, state):
        payload = json.dumps(
            {"version": STATE_VERSION, "started": state.started},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        sealed, mode = _seal(payload, self.key)
        envelope = {
            "version": STATE_VERSION,
            "encryption": mode,
            "payload": sealed.hex(),
            "hmac": _hmac_tag(self.key or b"", sealed).hex(),
        }
        self._atomic_write(
            self._path(VOLATILE_NAME),
            json.dumps(envelope, sort_keys=True).encode("utf-8"),
        )

    def load_volatile(self):
        try:
            envelope = self._read_envelope(VOLATILE_NAME)
        except FileNotFoundError:
            return None
        sealed = bytes.fromhex(envelope["payload"])
        if not hmac.compare_digest(
            _hmac_tag(self.key or b"", sealed),
            bytes.fromhex(envelope["hmac"]),
        ):
            raise StateError("volatile state integrity check failed")
        payload = _unseal(sealed, self.key, envelope.get("encryption"))
        return json.loads(payload)

    def clear_volatile(self):
        try:
            os.remove(self._path(VOLATILE_NAME))
        except FileNotFoundError:
            pass

    def write_meta(self, config):
        meta = {
            "version": STATE_VERSION,
            "profile": config.to_dict(),
            "format": "swtpm-ra-state",
        }
        self._atomic_write(
            self._path(META_NAME),
            json.dumps(meta, sort_keys=True, indent=2).encode("utf-8"),
        )

    def _read_envelope(self, name):
        with open(self._path(name), "rb") as handle:
            envelope = json.loads(handle.read().decode("utf-8"))
        if int(envelope.get("version", 0)) != STATE_VERSION:
            raise StateError(
                "unsupported envelope version: %r" % envelope.get("version")
            )
        return envelope

    def _atomic_write(self, path, blob):
        directory = os.path.dirname(path)
        fd, tmp_path = tempfile.mkstemp(prefix=".tmp-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(blob)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_path, path)
            directory_fd = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            try:
                os.remove(tmp_path)
            except FileNotFoundError:
                pass
            raise


class MemoryStateStore(StateStore):
    """In-memory store used by unit tests and ephemeral instances."""

    def __init__(self):
        self._permanent = None
        self._volatile = None

    def exists(self):
        return self._permanent is not None

    def save_permanent(self, state):
        self._permanent = state.to_permanent_dict()

    def load_permanent(self, config):
        if self._permanent is None:
            raise FileNotFoundError("no permanent state in memory store")
        return TPMState.from_permanent_dict(
            json.loads(json.dumps(self._permanent)), config
        )

    def save_volatile(self, state):
        self._volatile = {"version": STATE_VERSION, "started": state.started}

    def load_volatile(self):
        return (
            dict(self._volatile) if self._volatile is not None else None
        )

    def clear_volatile(self):
        self._volatile = None


def state_store_from_uri(uri, key=None):
    """Build a StateStore from a `file://` or `memory://` URI."""
    if uri is None or uri == "memory://":
        return MemoryStateStore()
    if uri.startswith("file://"):
        return FileStateStore(uri[len("file://"):], key=key)
    raise StateError("unsupported state store URI: %r" % uri)
