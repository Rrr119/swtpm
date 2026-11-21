"""
 config.py - declarative TPM configuration and PCR policy presets.

 A TPMConfig describes everything that distinguishes one simulated TPM
 profile from another: the active PCR hash banks, the number of PCR
 registers per bank, which PCRs can be reset by the caller, the command
 backend and the state-store location.
"""

import copy
import json
import os

from .codec import (
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
    NAME_TO_ALG,
)

SUPPORTED_ALGS = (
    TPM_ALG_SHA1,
    TPM_ALG_SHA256,
    TPM_ALG_SHA384,
    TPM_ALG_SHA512,
)

# TPM 2.0 devices implement 24 PCR registers per bank (index 0..23).
DEFAULT_PCR_COUNT = 24

# PCR 16..23 are the dynamic/resettable range on a typical TPM.
DEFAULT_RESETTABLE = tuple(range(16, 24))


class ConfigError(ValueError):
    """Raised when a configuration is invalid."""


class TPMConfig:
    """Immutable-ish description of a simulated TPM profile."""

    def __init__(
        self,
        name,
        banks=("sha256",),
        pcr_count=DEFAULT_PCR_COUNT,
        resettable_pcrs=DEFAULT_RESETTABLE,
        backend_uri="local://",
        state_uri=None,
        encrypted_state=False,
        state_key=None,
        fips=False,
    ):
        self.name = str(name)
        self.banks = tuple(self._normalize_banks(banks))
        self.pcr_count = int(pcr_count)
        self.resettable_pcrs = tuple(sorted(set(int(i) for i in resettable_pcrs)))
        self.backend_uri = str(backend_uri)
        self.state_uri = state_uri
        self.encrypted_state = bool(encrypted_state)
        self.state_key = state_key
        self.fips = bool(fips)
        self.validate()

    @staticmethod
    def _normalize_banks(banks):
        if isinstance(banks, str):
            banks = [banks]
        normalized = []
        for bank in banks:
            if isinstance(bank, int):
                normalized.append(bank)
            else:
                name = str(bank).lower().replace("-", "")
                if name not in NAME_TO_ALG:
                    raise ConfigError("unsupported PCR hash bank: %r" % bank)
                normalized.append(NAME_TO_ALG[name])
        return normalized

    def validate(self):
        if not self.name:
            raise ConfigError("config name must not be empty")
        if not self.banks:
            raise ConfigError("at least one PCR bank is required")
        if len(set(self.banks)) != len(self.banks):
            raise ConfigError("duplicate PCR banks: %r" % (self.banks,))
        for alg in self.banks:
            if alg not in SUPPORTED_ALGS:
                raise ConfigError("unsupported PCR algorithm id: 0x%x" % alg)
        if self.fips and TPM_ALG_SHA1 in self.banks:
            raise ConfigError("FIPS profile must not enable the SHA1 bank")
        if self.pcr_count <= 0 or self.pcr_count > 255:
            raise ConfigError("pcr_count must be in 1..255")
        for index in self.resettable_pcrs:
            if not 0 <= index < self.pcr_count:
                raise ConfigError(
                    "resettable PCR %d out of range 0..%d"
                    % (index, self.pcr_count - 1)
                )
        if self.state_key is not None and len(self.state_key) not in (16, 24, 32):
            raise ConfigError("state_key must be 16, 24 or 32 bytes")

    def bank_names(self):
        from .codec import ALG_NAME

        return tuple(ALG_NAME[alg] for alg in self.banks)

    def to_dict(self):
        return {
            "name": self.name,
            "banks": list(self.bank_names()),
            "pcr_count": self.pcr_count,
            "resettable_pcrs": list(self.resettable_pcrs),
            "backend_uri": self.backend_uri,
            "state_uri": self.state_uri,
            "encrypted_state": self.encrypted_state,
            "fips": self.fips,
        }

    @classmethod
    def from_dict(cls, data):
        data = dict(data)
        data.pop("state_key", None)
        return cls(**data)

    def to_json(self, **kwargs):
        return json.dumps(self.to_dict(), sort_keys=True, **kwargs)

    @classmethod
    def from_json(cls, text):
        return cls.from_dict(json.loads(text))

    def with_state(self, state_uri, **overrides):
        """Return a copy bound to a concrete state-store location."""
        data = self.to_dict()
        data["state_uri"] = state_uri
        data.update(overrides)
        copy = self.__class__.from_dict(data)
        copy.state_key = self.state_key
        return copy

    def __repr__(self):
        return "TPMConfig(name=%r, banks=%r)" % (self.name, self.bank_names())


def _fips_preset():
    return TPMConfig(
        name="fips-sha256",
        banks=("sha256",),
        fips=True,
        resettable_pcrs=(16, 17, 18, 19, 20, 21, 22, 23),
    )


CONFIG_PRESETS = {
    # 1. TPM 2.0 factory default: SHA1+SHA256 banks, 24 PCRs.
    "default": TPMConfig(
        name="default",
        banks=("sha1", "sha256"),
        resettable_pcrs=tuple(range(16, 24)),
    ),
    # 2. FIPS / hardened profile: SHA1 disabled.
    "fips": _fips_preset(),
    # 3. Multi-bank attestation profile: all common banks enabled.
    "multibank": TPMConfig(
        name="multibank",
        banks=("sha256", "sha384", "sha512"),
        resettable_pcrs=(16, 17, 18, 19, 20, 21, 22, 23),
    ),
    # 4. Reduced/embedded profile: fewer PCRs, no resettable dynamic PCRs.
    "minimal": TPMConfig(
        name="minimal",
        banks=("sha256",),
        pcr_count=8,
        resettable_pcrs=(),
    ),
    # 5. Remote profile: commands are dispatched over a UNIX socket.
    "socket": TPMConfig(
        name="socket",
        banks=("sha256", "sha384"),
        backend_uri="unix://swtpm-ra.sock",
        resettable_pcrs=(16, 17, 18, 19, 20, 21, 22, 23),
    ),
}


def get_preset(name):
    """Return a fresh copy of a named configuration preset."""
    if name not in CONFIG_PRESETS:
        raise ConfigError(
            "unknown preset %r; choose from %s"
            % (name, ", ".join(sorted(CONFIG_PRESETS)))
        )
    preset = CONFIG_PRESETS[name]
    return copy.deepcopy(preset)


def load_config(path):
    """Load a TPMConfig from a JSON file.

    A bare preset name stored in the file ("default") is also accepted so
    that small test fixtures can reference a preset directly.
    """
    with open(path, "r", encoding="utf-8") as handle:
        text = handle.read().strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ConfigError("invalid JSON config %s: %s" % (path, exc)) from exc
    if isinstance(data, str):
        return get_preset(data)
    if not isinstance(data, dict):
        raise ConfigError("config root must be an object or a preset name")
    data.setdefault("name", os.path.splitext(os.path.basename(path))[0])
    return TPMConfig.from_dict(data)
