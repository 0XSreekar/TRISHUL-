# SPDX-License-Identifier: Apache-2.0
"""``trishul bench`` command (registered from ``trishul.cli.main``)."""

import argparse
import json
from typing import Any


def register(top: Any) -> None:
    p = top.add_parser("bench", help="run benchmarks and write bench/results.json")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--export-deck",
        action="store_true",
        help="write docs/deck-numbers.md from the existing bench/results.json (no benchmark run)",
    )
    p.add_argument(
        "--agentdojo-blocks",
        action="store_true",
        help="only add the with-TRISHUL block diagnostic to the existing results.json",
    )


def run(args: argparse.Namespace) -> int:
    from trishul.bench.report import RESULTS, merge_agentdojo_blocks, write_results

    if args.export_deck:
        from trishul.bench.deck import export_deck

        print(f"wrote {export_deck()}")
        return 0
    if args.agentdojo_blocks:
        diag = merge_agentdojo_blocks(args.seed)
        print(f"updated {RESULTS}")
        print(json.dumps({k: diag.get(k) for k in ("status", "blocked_calls", "by_decision")}))
        return 0
    results = write_results(args.seed)
    ind = results["suites"]["india"]
    print(f"wrote {RESULTS}")
    print(json.dumps({"with_trishul": ind["with_trishul"], "without": ind["without"]}))
    print(f"agentdojo: {results['suites']['agentdojo']['status']}")
    return 0
