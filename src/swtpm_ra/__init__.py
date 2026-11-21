"""
 swtpm_ra - remote-attestation oriented swtpm simulation layer.

 The package adds three building blocks on top of a TPM-style command
 interface:

   * pluggable command backends (in-process and UNIX-domain socket),
   * declarative PCR policies (hash banks, PCR count, resettable range),
   * versioned state persistence with atomic writes and optional
     encryption/integrity protection.

 Quotes produced after migrating the persisted state to a fresh instance
 are byte-for-byte identical because the attestation key is persisted and
 the signature algorithm (Ed25519) and attestation encoding are fully
 deterministic.
"""

from .config import TPMConfig, CONFIG_PRESETS, load_config, get_preset
from .pcr import PCRPolicy
from .keys import KeyHierarchy
from .quote import AttestBlob, quote, verify_quote
from .state import TPMState, FileStateStore, MemoryStateStore, state_store_from_uri
from .backend import (
    CommandBackend,
    LocalCommandBackend,
    SocketCommandBackend,
    SocketCommandServer,
    backend_from_uri,
)
from .tpm import SwtpmRA, TPMNotStartedError, TPMCommandError

__all__ = [
    "TPMConfig",
    "CONFIG_PRESETS",
    "load_config",
    "get_preset",
    "PCRPolicy",
    "KeyHierarchy",
    "AttestBlob",
    "quote",
    "verify_quote",
    "TPMState",
    "FileStateStore",
    "MemoryStateStore",
    "state_store_from_uri",
    "CommandBackend",
    "LocalCommandBackend",
    "SocketCommandBackend",
    "SocketCommandServer",
    "backend_from_uri",
    "SwtpmRA",
    "TPMNotStartedError",
    "TPMCommandError",
]

__version__ = "1.0.0"
