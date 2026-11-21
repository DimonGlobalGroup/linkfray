# LinkFray

A read-only symlink chain auditor. LinkFray walks a directory tree
without ever following a directory symlink, resolves every link's
chain hop by hop, and reports what is actually wrong — dangling
targets, resolution loops, relative links that escape the scanned
root, absolute targets, over-long chains, and messy targets — as
named rules with severities, in a deterministic text or JSON report.

It never fixes anything. There is no delete mode, no convert mode,
no repair mode to reach for by accident: LinkFray's whole write
surface is stdout. Run it before a tree copy, a backup restore, or
a release packaging, and find out which links will fray before they
do.

## Why not `find . -xtype l`?

That answers one question: is this link broken right now? LinkFray
answers the follow-ups that matter in practice:

- **Where does the chain die?** Chains are resolved hop by hop, so
  a link pointing at another link pointing at nothing is reported
  with its measured hop count, not a shrug.
- **Does it loop?** Self-links and cycles are their own finding,
  distinct from dangling — a loop is a configuration bug, not a
  missing file.
- **Does it escape?** A relative link whose resolved target lands
  outside the root it was found under is flagged. That is the link
  that was harmless in the original tree and becomes a path out of
  the sandbox after a copy or a restore, and broken-link finders
  never mention it.
- **Will it travel?** Absolute targets and redundant, messy target
  paths are reported at low severity — portability notes, not
  alarms.

## Install

One file, Python 3.10+, standard library only. Copy `linkfray.py`
anywhere and run it:

```sh
python3 linkfray.py scan /path/to/tree
```

## Usage

```text
linkfray scan DIR [DIR ...] [--json]
              [--min-severity {low,medium,high}]
              [--fail-on {low,medium,high,never}]
              [--max-chain N]
```

- `--json` — emit the report as stable, sorted JSON for CI or
  review tooling.
- `--min-severity` — only report findings at or above this
  severity (default `low`: report everything). Filtered findings
  are excluded from the counts as well.
- `--fail-on` — exit 1 when a finding at or above this severity
  exists (default `high`); `never` always exits 0 on a completed
  scan.
- `--max-chain N` — flag chains longer than N hops as `long-chain`
  (default 8).

Exit codes: `0` = scan completed, nothing at or above the
`--fail-on` severity; `1` = at least one such finding; `2` = usage
error or a scan root that is missing or not a directory.

## Example

```text
$ python3 linkfray.py scan /tmp/lf-demo/tree
HIGH dangling 1 /tmp/lf-demo/tree/bad -> gone.txt
MEDIUM escapes-root 1 /tmp/lf-demo/tree/escapee -> ../outside.txt
HIGH loop - /tmp/lf-demo/tree/loop-a -> loop-b
HIGH loop - /tmp/lf-demo/tree/loop-b -> loop-a
linkfray: 2 dirs scanned, 5 links, 4 findings (3 high, 1 medium, 0 low), 0 errors
```

(exit code 1, because high-severity findings exist at the default
`--fail-on high`.)

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `dangling` | high | The chain resolves to a target that does not exist. |
| `loop` | high | The chain revisits a path (self-link or cycle) or exceeds 255 hops. A looping link is never also reported as dangling. |
| `escapes-root` | medium | A relative link whose resolved target lies outside the scan root it was found under. |
| `absolute-target` | low | The raw target is an absolute path — it will not survive the tree moving. |
| `long-chain` | low | The chain took more than `--max-chain` hops to resolve. |
| `messy-target` | low | The raw target contains redundant separators, `/./`, resolvable `..` components, or a trailing separator. |

A single link can produce several findings, one per rule. Findings
are sorted by path, then rule, and the JSON report is
byte-identical across runs on an unchanged tree.

## Honest limitations

- Chain resolution follows links whose full path is itself a
  symlink. A path that passes *through* a symlinked directory
  component mid-chain is resolved by the operating system at the
  existence check, so its intermediate hops are not counted.
- The escape test compares `realpath` results lexically after OS
  resolution; it is a report, not a security boundary. Treat an
  `escapes-root` finding as "look at this link", not as proof of
  safety or danger.
- Link targets are reported as written. If your tree contains
  links whose targets are sensitive names, the report will contain
  those names — it is a local report for the tree's owner.
- Hard links are out of scope: they are not symlinks, and this
  tool audits symlinks only.

## Tests

```sh
python3 -m unittest test_linkfray -v
```

## License

MIT — see `LICENSE`. Copyright (c) 2026 Dimon Global Group.
