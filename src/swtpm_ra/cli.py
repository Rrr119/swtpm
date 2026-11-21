"""
 cli.py - command line front end for the swtpm_ra simulation layer.

 Examples:
   python -m swtpm_ra presets
   python -m swtpm_ra init --config fips --state file:///tmp/tpm-state
   python -m swtpm_ra extend --index 10 --data hello --state file:///tmp/tpm-state
   python -m swtpm_ra quote --nonce deadbeef --state file:///tmp/tpm-state
   python -m swtpm_ra migrate --state file:///tmp/a --target file:///tmp/b
"""

import argparse
import json
import sys

from .codec import NAME_TO_ALG, TPM_SU_CLEAR
from .config import CONFIG_PRESETS, get_preset, load_config
from .tpm import SwtpmRA


def _resolve_config(args):
    if args.config_file:
        return load_config(args.config_file)
    return get_preset(args.config)


def _bind_state(config, args):
    if args.state:
        return config.with_state(args.state)
    return config


def _make_tpm(args, auto_start=False):
    config = _bind_state(_resolve_config(args), args)
    tpm = SwtpmRA(config)
    if auto_start:
        tpm.startup(TPM_SU_CLEAR)
    return tpm


def cmd_presets(args):
    for name in sorted(CONFIG_PRESETS):
        preset = CONFIG_PRESETS[name]
        print(
            "%-10s banks=%s pcr_count=%d resettable=%s backend=%s"
            % (
                name,
                ",".join(preset.bank_names()),
                preset.pcr_count,
                list(preset.resettable_pcrs),
                preset.backend_uri,
            )
        )
    return 0


def cmd_init(args):
    tpm = _make_tpm(args)
    tpm.startup(TPM_SU_CLEAR)
    tpm.save_state()
    print(
        json.dumps(
            {
                "profile": tpm.config.name,
                "state_uri": tpm.config.state_uri or "memory://",
                "banks": list(tpm.config.bank_names()),
            },
            indent=2,
        )
    )
    return 0


def cmd_extend(args):
    tpm = _make_tpm(args, auto_start=True)
    data = args.data.encode("utf-8")
    tpm.pcr_extend(args.index, data)
    tpm.save_state()
    print(json.dumps({"pcr": args.index, "data": args.data}, indent=2))
    return 0


def cmd_reset(args):
    tpm = _make_tpm(args, auto_start=True)
    tpm.pcr_reset(args.index)
    tpm.save_state()
    print(json.dumps({"pcr": args.index, "reset": True}, indent=2))
    return 0


def cmd_read(args):
    tpm = _make_tpm(args, auto_start=True)
    algorithm = NAME_TO_ALG[args.algorithm.lower().replace("-", "")]
    digest = tpm.pcr_read(algorithm, args.index)
    print(json.dumps({"pcr": args.index, "digest": digest.hex()}, indent=2))
    return 0


def cmd_quote(args):
    tpm = _make_tpm(args, auto_start=True)
    if args.nonce.startswith("0x"):
        nonce = bytes.fromhex(args.nonce[2:])
    else:
        nonce = args.nonce.encode("utf-8")
    signed = tpm.quote(nonce)
    tpm.save_state()
    print(json.dumps(signed.to_dict(), indent=2, sort_keys=True))
    return 0


def cmd_verify(args):
    tpm = _make_tpm(args, auto_start=True)
    with open(args.quote, "r", encoding="utf-8") as handle:
        data = json.load(handle)
    from .quote import AttestBlob, Quote

    composite = {
        int(algorithm): bytes.fromhex(digest)
        for algorithm, digest in data["pcr_composite"].items()
    }
    attest = AttestBlob(
        nonce=bytes.fromhex(data["nonce"]),
        pcr_composite=composite,
        clock=data["clock"],
        magic=data["magic"],
        type_tag=data["type_tag"],
    )
    signed = Quote(
        attest,
        bytes.fromhex(data["signature"]),
        bytes.fromhex(data["ak_public"]),
        algorithm=data["signature_algorithm"],
    )
    tpm.verify_quote(signed)
    print(json.dumps({"verified": True}, indent=2))
    return 0


def cmd_migrate(args):
    tpm = _make_tpm(args, auto_start=True)
    if args.extend:
        tpm.pcr_extend(args.extend_index or 0, args.extend.encode("utf-8"))
    before = tpm.quote(b"migration-check")
    migrated = tpm.migrate(target_state_uri=args.target)
    after = migrated.quote(b"migration-check")
    result = {
        "source": tpm.config.state_uri,
        "target": args.target,
        "quote_identical": before == after,
        "signature": after.signature.hex(),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["quote_identical"] else 1


def cmd_cap(args):
    tpm = _make_tpm(args, auto_start=True)
    print(json.dumps(tpm.config.to_dict(), indent=2, sort_keys=True))
    return 0


def build_parser():
    parser = argparse.ArgumentParser(
        prog="swtpm_ra",
        description="Remote-attestation oriented swtpm simulation layer.",
    )
    parser.add_argument(
        "--config",
        default="default",
        choices=sorted(CONFIG_PRESETS),
        help="named TPM configuration preset",
    )
    parser.add_argument("--config-file", help="JSON TPMConfig file")
    parser.add_argument("--state", help="state store URI, e.g. file:///path")

    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("presets", help="list the built-in configuration presets")

    sub.add_parser("init", help="initialize and persist a TPM state")

    extend = sub.add_parser("extend", help="extend a PCR")
    extend.add_argument("--index", type=int, required=True)
    extend.add_argument("--data", required=True)

    reset = sub.add_parser("reset", help="reset a resettable PCR")
    reset.add_argument("--index", type=int, required=True)

    read = sub.add_parser("read", help="read one PCR digest")
    read.add_argument("--index", type=int, required=True)
    read.add_argument("--algorithm", default="sha256")

    quote_cmd = sub.add_parser("quote", help="produce a signed quote")
    quote_cmd.add_argument("--nonce", required=True)

    verify = sub.add_parser("verify", help="verify a quote JSON file")
    verify.add_argument("--quote", required=True)

    migrate = sub.add_parser("migrate", help="migrate state and compare quotes")
    migrate.add_argument("--target", required=True)
    migrate.add_argument("--extend", help="optional data extended before migration")
    migrate.add_argument("--extend-index", type=int)

    sub.add_parser("cap", help="print the active configuration")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    handlers = {
        "presets": cmd_presets,
        "init": cmd_init,
        "extend": cmd_extend,
        "reset": cmd_reset,
        "read": cmd_read,
        "quote": cmd_quote,
        "verify": cmd_verify,
        "migrate": cmd_migrate,
        "cap": cmd_cap,
    }
    try:
        return handlers[args.command](args)
    except Exception as exc:  # surface a clean CLI error
        print("swtpm_ra: %s" % exc, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
