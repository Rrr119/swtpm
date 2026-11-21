# swtpm_ra - remote-attestation TPM simulation layer

`swtpm_ra` adds a remote-attestation oriented simulation layer for
exercising multiple TPM configurations without requiring libtpms. It is
self-contained Python (standard library plus `cryptography`) and shares
the TPM 2.0 command/response framing used by swtpm so the concepts map
directly onto the C implementation.

## Building blocks

- **Command backend** (`backend.py`): every TPM command travels as a TPM2
 style frame through a `CommandBackend`. `LocalCommandBackend` dispatches
 in-process; `SocketCommandBackend` forwards the same frames over a UNIX
 domain socket to a multithreaded `SocketCommandServer`. Backends are
 selected with `local://` or `unix://<path>` URIs and are interchangeable.
- **PCR policy** (`pcr.py`, `config.py`): each configuration declares its
 hash banks (SHA1/SHA256/SHA384/SHA512), PCR count and resettable index
 range. Extend follows `PCR_new = H(PCR_old || data)`, reset is refused
 for indices outside the policy, and each bank exposes a canonical PCR
 composite used by quotes.
- **State persistence** (`state.py`): the permanent state (EK/AK hierarchy,
 PCRs, clock, counters) is serialized in a versioned envelope with
 atomic temp-file/rename writes, HMAC-SHA256 integrity tags and optional
 AES-GCM encryption. Volatile state tracks whether the TPM is started;
 a missing volatile file forces `TPM_SU_CLEAR` semantics on next startup.
- **Deterministic quotes** (`quote.py`): the AK is an Ed25519 key whose
 private bytes are persisted. Ed25519 and the canonical attestation
 encoding are deterministic, so the same state always yields the same
 signature - including after restart or migration to another instance.

## The five configurations

| Preset | Banks | PCRs | Resettable | Backend |
| --- | --- | --- | --- | --- |
| `default` | sha1, sha256 | 24 | 16..23 | local |
| `fips` | sha256 | 24 | 16..23 | local, SHA1 rejected |
| `multibank` | sha256, sha384, sha512 | 24 | 16..23 | local |
| `minimal` | sha256 | 8 | none | local |
| `socket` | sha256, sha384 | 24 | 16..23 | unix socket |

Presets live in `config.CONFIG_PRESETS`; custom profiles can be passed as
JSON via `TPMConfig.from_json` / `load_config`.

## Migration guarantee

`SwtpmRA.migrate(target_state_uri=...)` flushes the permanent state,
copies the state tree to the target store and hands it to a fresh
instance that restores it with `TPM_SU_STATE` semantics. Keys, PCR
composites and clock are preserved, therefore:

```python
before = source.quote(nonce)
target = source.migrate(target_state_uri="file:///tmp/target")
assert target.quote(nonce) == before  # blob and signature byte-identical
```

## CLI

```
python -m swtpm_ra presets
python -m swtpm_ra --config fips --state file:///tmp/tpm init
python -m swtpm_ra --config fips --state file:///tmp/tpm extend --index 10 --data event
python -m swtpm_ra --config fips --state file:///tmp/tpm quote --nonce deadbeef
python -m swtpm_ra --config fips --state file:///tmp/a migrate --target file:///tmp/b
```

## Tests

The suite under `tests/swtpm_ra` uses only the standard library
`unittest` runner:

```
tests/swtpm_ra/run_tests
```

It contains one module per configuration (the five required
configuration tests) plus frame-codec and persistence/tamper/migration
tests. Every configuration test asserts PCR policy behavior and that
restart and migration reproduce the original quote bytes.
