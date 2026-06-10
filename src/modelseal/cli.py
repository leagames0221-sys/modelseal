"""modelseal CLI: scan / approve / diff.

Exit code reflects the verdict (PASS=0, WARN=1, FAIL=2) so CI can gate on it (AC-2).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from modelseal.core.baseline import Baseline
from modelseal.core.contracts import Report
from modelseal.core.engine import Engine
from modelseal.core.render import render
from modelseal.registry import default_scanners


def _engine() -> Engine:
    return Engine(default_scanners())


def _parse_expect(pairs: list[str] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in pairs or []:
        key, _, val = item.partition("=")
        if not val:
            raise SystemExit(f"--expect-hash expects NAME=SHA256, got: {item!r}")
        out[key] = val
    return out


def _cmd_scan(args) -> int:
    expected = _parse_expect(args.expect_hash)
    report = _engine().scan_path(Path(args.path), expected or None)
    _maybe_explain(report, args)
    print(render(report, args.format))
    return report.exit_code


def _cmd_approve(args) -> int:
    baseline = Baseline.approve(Path(args.path), _engine())
    baseline.save(Path(args.manifest))
    print(f"approved {len(baseline.artifacts)} artifact(s) -> {args.manifest}")
    return 0


def _cmd_diff(args) -> int:
    baseline = Baseline.load(Path(args.manifest))
    findings = baseline.diff(Path(args.path), _engine())
    report = Report(findings=findings)
    _maybe_explain(report, args)
    print(render(report, args.format))
    return report.exit_code


def _maybe_explain(report: Report, args) -> None:
    if not getattr(args, "explain", False):
        return
    # Explanation layer is optional and never changes the verdict (AC-21..23).
    try:
        from modelseal.packs.explain.ollama_provider import OllamaProvider

        report.explanation = OllamaProvider().explain(report.findings)
    except Exception as exc:  # provider unreachable -> skip, deterministic core stands
        report.explanation = f"(explanation layer unavailable: {type(exc).__name__})"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="modelseal", description="AI model artifact inspection gate")
    sub = p.add_subparsers(dest="command", required=True)

    common_fmt = dict(choices=["human", "json", "sarif"], default="human")

    s = sub.add_parser("scan", help="inspect an artifact or directory")
    s.add_argument("path")
    s.add_argument("--format", **common_fmt)
    s.add_argument("--expect-hash", action="append", metavar="NAME=SHA256",
                   help="expected sha256 for an artifact (path or filename)")
    s.add_argument("--explain", action="store_true", help="add optional LLM explanation")
    s.set_defaults(func=_cmd_scan)

    a = sub.add_parser("approve", help="record an approval baseline manifest")
    a.add_argument("path")
    a.add_argument("--manifest", required=True)
    a.set_defaults(func=_cmd_approve)

    d = sub.add_parser("diff", help="compare against an approval baseline")
    d.add_argument("path")
    d.add_argument("--manifest", required=True)
    d.add_argument("--format", **common_fmt)
    d.add_argument("--explain", action="store_true", help="add optional LLM explanation")
    d.set_defaults(func=_cmd_diff)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
