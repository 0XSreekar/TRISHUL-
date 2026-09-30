"""``trishul policy compile|check|eval``."""

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from trishul.contracts.canonical import canonical_json
from trishul.policy.compiler import PolicyCompileFailure, compile_files
from trishul.policy.evaluator import evaluate_raw


def _compile(paths: Sequence[Path]) -> int:
    try:
        policy = compile_files(paths)
    except PolicyCompileFailure as failure:
        for error in failure.errors:
            print(error, file=sys.stderr)
        print(f"{len(failure.errors)} error(s)", file=sys.stderr)
        return 1
    print(policy.canonical())
    print(f"digest: {policy.digest}")
    return 0


def _check(paths: Sequence[Path]) -> int:
    try:
        policy = compile_files(paths)
    except PolicyCompileFailure as failure:
        for error in failure.errors:
            print(error, file=sys.stderr)
        return 1
    print(f"OK {policy.digest}")
    return 0


def _eval(policy_dir: Path, call_file: Path) -> int:
    try:
        policy = compile_files([policy_dir])
        raw = json.loads(call_file.read_text(encoding="utf-8"))
    except PolicyCompileFailure as failure:
        for error in failure.errors:
            print(error, file=sys.stderr)
        return 1
    except (OSError, ValueError) as exc:
        print(f"{call_file}: cannot read call: {exc}", file=sys.stderr)
        return 2
    if isinstance(raw, dict) and "call" not in raw:  # bare ToolCall: add a default context
        raw = {"call": raw, "context": {"now": datetime.now(UTC).isoformat()}}
    print(canonical_json(evaluate_raw(policy, raw).model_dump(mode="json")))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="trishul")
    top = parser.add_subparsers(dest="group", required=True)
    policy = top.add_parser("policy", help="policy tools").add_subparsers(dest="cmd", required=True)
    for name, help_text in (("compile", "compile and print canonical JSON"), ("check", "validate")):
        p = policy.add_parser(name, help=help_text)
        p.add_argument("paths", nargs="+", type=Path)
    ev = policy.add_parser("eval", help="evaluate a call against a policy directory")
    ev.add_argument("policy_dir", type=Path)
    ev.add_argument("call", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    match args.cmd:
        case "compile":
            return _compile(args.paths)
        case "check":
            return _check(args.paths)
        case _:
            return _eval(args.policy_dir, args.call)


if __name__ == "__main__":
    sys.exit(main())
