"""
 pcr.py - PCR policy: hash banks, extend/reset rules and PCR composites.

 A PCRPolicy owns one register bank per configured hash algorithm. Every
 bank starts at the all-zero digest of its hash length. Extend follows the
 TPM2 rule PCR_new := H(PCR_old || data) and reset is only permitted for
 PCR indices listed in the active policy.
"""

import hashlib

from .codec import ALG_DIGEST_SIZE, ALG_NAME, TPM_RC_PCR, TPM_RC_VALUE


class PCRError(Exception):
    """Raised for policy violations; carries a TPM2-style response code."""

    def __init__(self, message, response_code=TPM_RC_PCR):
        super().__init__(message)
        self.response_code = response_code


class PCRBank:
    """A single hash-algorithm bank holding `pcr_count` registers."""

    def __init__(self, algorithm, pcr_count, values=None):
        self.algorithm = algorithm
        self.pcr_count = pcr_count
        digest_size = ALG_DIGEST_SIZE[algorithm]
        if values is None:
            self.values = [b"\x00" * digest_size for _ in range(pcr_count)]
        else:
            if len(values) != pcr_count:
                raise PCRError(
                    "bank 0x%x expects %d PCR values, got %d"
                    % (algorithm, pcr_count, len(values))
                )
            self.values = [bytes(value) for value in values]
            for value in self.values:
                if len(value) != digest_size:
                    raise PCRError(
                        "bank 0x%x expects %d byte digests"
                        % (algorithm, digest_size)
                    )

    def _hash(self, data):
        return hashlib.new(ALG_NAME[self.algorithm], data).digest()

    def extend(self, index, data):
        self._check_index(index)
        self.values[index] = self._hash(self.values[index] + bytes(data))

    def reset(self, index):
        self._check_index(index)
        digest_size = ALG_DIGEST_SIZE[self.algorithm]
        self.values[index] = b"\x00" * digest_size

    def read(self, index):
        self._check_index(index)
        return self.values[index]

    def composite(self):
        """Return the concatenation of all register values in the bank."""
        return b"".join(self.values)

    def _check_index(self, index):
        if not isinstance(index, int) or not 0 <= index < self.pcr_count:
            raise PCRError(
                "PCR index %r out of range 0..%d"
                % (index, self.pcr_count - 1),
                TPM_RC_VALUE,
            )

    def to_dict(self):
        return {
            "algorithm": self.algorithm,
            "values": [value.hex() for value in self.values],
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            data["algorithm"],
            len(data["values"]),
            values=[bytes.fromhex(value) for value in data["values"]],
        )


class PCRPolicy:
    """All PCR banks of one TPM plus the resettable-index policy."""

    def __init__(self, algorithms, pcr_count, resettable_pcrs, banks=None):
        self.pcr_count = pcr_count
        self.resettable_pcrs = frozenset(resettable_pcrs)
        if banks is None:
            self.banks = {
                algorithm: PCRBank(algorithm, pcr_count)
                for algorithm in algorithms
            }
        else:
            self.banks = {bank.algorithm: bank for bank in banks}
            missing = set(algorithms) - set(self.banks)
            if missing:
                raise PCRError("missing PCR banks after restore: %r" % missing)

    @classmethod
    def from_config(cls, config):
        return cls(
            config.banks,
            config.pcr_count,
            config.resettable_pcrs,
        )

    def algorithms(self):
        return tuple(sorted(self.banks))

    def extend(self, index, data, algorithms=None):
        """Extend one PCR across all (or a selected set of) banks."""
        if algorithms is None:
            algorithms = self.algorithms()
        for algorithm in algorithms:
            self._bank(algorithm).extend(index, data)

    def reset(self, index, algorithms=None):
        if index not in self.resettable_pcrs:
            raise PCRError(
                "PCR %d is not resettable under the active policy" % index
            )
        if algorithms is None:
            algorithms = self.algorithms()
        for algorithm in algorithms:
            self._bank(algorithm).reset(index)

    def read(self, algorithm, index):
        return self._bank(algorithm).read(index)

    def snapshot(self):
        """Return every bank composite keyed by algorithm id."""
        return {
            algorithm: bank.composite()
            for algorithm, bank in sorted(self.banks.items())
        }

    def _bank(self, algorithm):
        try:
            return self.banks[algorithm]
        except KeyError:
            raise PCRError(
                "PCR bank 0x%x is not enabled in this profile" % algorithm,
                TPM_RC_VALUE,
            ) from None

    def to_dict(self):
        return {
            "pcr_count": self.pcr_count,
            "resettable_pcrs": sorted(self.resettable_pcrs),
            "banks": [
                self.banks[algorithm].to_dict()
                for algorithm in sorted(self.banks)
            ],
        }

    @classmethod
    def from_dict(cls, data):
        banks = [PCRBank.from_dict(bank) for bank in data["banks"]]
        return cls(
            tuple(bank.algorithm for bank in banks),
            data["pcr_count"],
            tuple(data["resettable_pcrs"]),
            banks=banks,
        )
