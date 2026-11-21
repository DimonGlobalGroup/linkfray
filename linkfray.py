#!/usr/bin/env python3
"""LinkFray — a read-only symlink chain auditor.

Audits every symlink under one or more directory roots: walks without
ever following a directory symlink, resolves each link's chain hop by
hop, and reports findings under named rules (dangling targets,
resolution loops, relative links that escape their scan root,
absolute targets, over-long chains, messy targets) as a deterministic
text or JSON report.

LinkFray never modifies anything. It has no delete, convert, or fix
mode; its whole write surface is stdout. File contents are never
opened — only readlink/lstat-class metadata is read.

Usage:
    python3 linkfray.py scan DIR [DIR ...] [--json]
                         [--min-severity {low,medium,high}]
                         [--fail-on {low,medium,high,never}]
                         [--max-chain N]

Exit codes: 0 = no finding at or above the --fail-on severity;
1 = at least one such finding; 2 = usage or scan-root error.
"""

import argparse
import json
import os
import sys

VERSION = "1.0.0"

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}

RULE_SEVERITY = {
    "dangling": "high",
    "loop": "high",
    "escapes-root": "medium",
    "absolute-target": "low",
    "long-chain": "low",
    "messy-target": "low",
}

MAX_HOPS = 255


def resolve_chain(link_path):
    """Resolve a symlink's chain hop by hop.

    Returns (final_path, hops, looped). ``final_path`` is the first
    path in the chain that is not itself a symlink, ``hops`` is the
    number of symlink traversals taken to reach it (the audited link
    itself counts as the first hop), and ``looped`` is True when the
    chain revisits a path or exceeds MAX_HOPS hops — in that case
    ``final_path`` is None.
    """
    current = os.path.abspath(link_path)
    visited = set()
    hops = 0
    while os.path.islink(current):
        if current in visited or hops >= MAX_HOPS:
            return None, hops, True
        visited.add(current)
        hops += 1
        raw = os.readlink(current)
        if os.path.isabs(raw):
            current = os.path.normpath(raw)
        else:
            current = os.path.normpath(
                os.path.join(os.path.dirname(current), raw)
            )
    return current, hops, False


def audit_link(link_path, root_real, max_chain):
    """Audit one symlink; return a list of finding dicts."""
    raw = os.readlink(link_path)
    final, hops, looped = resolve_chain(link_path)
    rules = []

    if looped:
        rules.append("loop")
    else:
        if not os.path.exists(final):
            rules.append("dangling")
        if not os.path.isabs(raw):
            final_real = os.path.realpath(final)
            try:
                inside = os.path.commonpath([root_real, final_real]) == root_real
            except ValueError:
                inside = False
            if not inside:
                rules.append("escapes-root")

    if os.path.isabs(raw):
        rules.append("absolute-target")
    if not looped and hops > max_chain:
        rules.append("long-chain")
    if os.path.normpath(raw) != raw:
        rules.append("messy-target")

    findings = []
    for rule in rules:
        findings.append(
            {
                "path": link_path,
                "rule": rule,
                "severity": RULE_SEVERITY[rule],
                "hops": None if looped else hops,
                "target": raw,
            }
        )
    return findings


def scan_root(root, max_chain):
    """Walk one root without following directory symlinks.

    Returns (findings, dirs_scanned, links_scanned, errors).
    """
    findings = []
    dirs_scanned = 0
    links_scanned = 0
    errors = 0
    root_real = os.path.realpath(root)

    def on_error(_exc):
        nonlocal errors
        errors += 1

    for dirpath, dirnames, filenames in os.walk(
        root, onerror=on_error, followlinks=False
    ):
        dirs_scanned += 1
        dirnames.sort()
        filenames.sort()
        for name in dirnames + filenames:
            path = os.path.join(dirpath, name)
            if os.path.islink(path):
                links_scanned += 1
                findings.extend(audit_link(path, root_real, max_chain))
    return findings, dirs_scanned, links_scanned, errors


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="linkfray",
        description="Read-only symlink chain auditor.",
    )
    parser.add_argument("--version", action="version", version=f"linkfray {VERSION}")
    sub = parser.add_subparsers(dest="command")
    scan = sub.add_parser("scan", help="Audit symlinks under one or more roots.")
    scan.add_argument("dirs", nargs="+", metavar="DIR")
    scan.add_argument("--json", action="store_true", help="Emit a JSON report.")
    scan.add_argument(
        "--min-severity",
        choices=["low", "medium", "high"],
        default="low",
        help="Only report findings at or above this severity (default: low).",
    )
    scan.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "never"],
        default="high",
        help="Exit 1 when a finding at or above this severity exists "
        "(default: high).",
    )
    scan.add_argument(
        "--max-chain",
        type=int,
        default=8,
        help="Flag chains longer than this many hops (default: 8).",
    )
    args = parser.parse_args(argv)

    if args.command != "scan":
        parser.print_usage(sys.stderr)
        return 2
    if args.max_chain < 0:
        print("linkfray: --max-chain must be >= 0", file=sys.stderr)
        return 2
    for d in args.dirs:
        if not os.path.isdir(d):
            print(f"linkfray: not a directory: {d}", file=sys.stderr)
            return 2

    all_findings = []
    total_dirs = 0
    total_links = 0
    total_errors = 0
    for d in args.dirs:
        f, dc, lc, ec = scan_root(d, args.max_chain)
        all_findings.extend(f)
        total_dirs += dc
        total_links += lc
        total_errors += ec

    min_rank = SEVERITY_ORDER[args.min_severity]
    shown = [
        f for f in all_findings if SEVERITY_ORDER[f["severity"]] >= min_rank
    ]
    shown.sort(key=lambda f: (f["path"], f["rule"]))

    counts = {"high": 0, "medium": 0, "low": 0}
    for f in shown:
        counts[f["severity"]] += 1

    if args.json:
        report = {
            "tool": "linkfray",
            "version": VERSION,
            "roots": args.dirs,
            "counts": {
                "dirs_scanned": total_dirs,
                "links_scanned": total_links,
                "errors": total_errors,
                "findings": len(shown),
                "high": counts["high"],
                "medium": counts["medium"],
                "low": counts["low"],
            },
            "findings": shown,
        }
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        for f in shown:
            hops = "-" if f["hops"] is None else str(f["hops"])
            print(
                f"{f['severity'].upper()} {f['rule']} {hops} "
                f"{f['path']} -> {f['target']}"
            )
        print(
            f"linkfray: {total_dirs} dirs scanned, {total_links} links, "
            f"{len(shown)} findings ({counts['high']} high, "
            f"{counts['medium']} medium, {counts['low']} low), "
            f"{total_errors} errors"
        )

    if args.fail_on == "never":
        return 0
    fail_rank = SEVERITY_ORDER[args.fail_on]
    if any(SEVERITY_ORDER[f["severity"]] >= fail_rank for f in shown):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
