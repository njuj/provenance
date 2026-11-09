"""provenance: is the package on npm / PyPI the code in its repository?
Exit codes: 0 nothing at or above --fail-on · 1 findings · 2 could not check."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

from . import __version__, compare, net, registry, source

ICON = {"critical": "✖", "high": "✖", "medium": "⚠", "low": "•", "info": "·"}
COLOR = {"critical": "1;31", "high": "31", "medium": "33", "low": "36", "info": "2"}
VERDICT = {"matches": ("✔ MATCHES", "1;32", "every published file is the file in the repository"),
           "consistent": ("✔ CONSISTENT", "32", "files that differ are build output, and none of them can do anything its source cannot"),
           "differs": ("✖ DIFFERS", "1;31", "the package contains code its repository does not explain"),
           "unverifiable": ("? UNVERIFIABLE", "33", "no matching source could be found")}


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="provenance", description="Check that a package on npm or PyPI is the code in its repository.")
    ap.add_argument("packages", nargs="+", help="npm:name[@version], pypi:name[==version], or a bare npm name")
    ap.add_argument("--repo", help="compare with this GitHub repository (owner/name) instead of the one the package names")
    ap.add_argument("--ref", help="compare with this commit, tag or branch")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--min-severity", choices=compare.SEVERITIES, default="low", help="hide findings below this (default: low)")
    ap.add_argument("--fail-on", choices=compare.SEVERITIES, default="high", help="exit 1 at or above this (default: high)")
    ap.add_argument("--no-color", action="store_true", help="plain output")
    ap.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _paint(enabled: bool):
    if enabled and os.name == "nt":
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x4)
    return (lambda s, c: f"\x1b[{c}m{s}\x1b[0m") if enabled else (lambda s, c: s)


def render(rep: compare.Report, min_sev: str, paint) -> str:
    r = rep.release
    out = [paint(f" {r.ecosystem}:{r.name}@{r.version}", "1") + paint(f"  {r.artifact}  ·  {len(r.files)} files", "2")]
    if rep.source:
        ref = rep.source.ref[:12] if len(rep.source.ref) == 40 else rep.source.ref
        out.append(paint(f"   source  github.com/{rep.source.repo} @ {ref}  ({rep.source.how})", "2"))
    label, color, why = VERDICT[rep.verdict]
    out.append(f"   {paint(label, color)}  {paint(why, '2')}")
    c = {k: len(v) for k, v in rep.piles.items()}
    out.append(paint(f"   {c['identical']} identical · {c['traced']} traced through source maps · {c['built']} built · "
                     f"{c['changed']} changed · {c['extra']} only in the package · {c['metadata']} metadata", "2"))
    shown = sorted((f for f in rep.findings if compare.RANK[f.severity] <= compare.RANK[min_sev]), key=lambda f: compare.RANK[f.severity])
    for f in shown[:40]:
        out.append(f"   {paint(f'{ICON[f.severity]} {f.severity.upper():<8}', COLOR[f.severity])} {f.title}")
        out.append(paint(f"              └ {f.detail}", "2"))
        for e in f.evidence[:3] if compare.RANK[f.severity] <= compare.RANK["high"] else []:
            out.append(paint(f"                + {e[:150]}", "35"))
    if len(shown) > 40:
        out.append(paint(f"   … and {len(shown) - 40} more (--json for all)", "2"))
    return "\n".join(out) + "\n"


def main(argv: list[str] | None = None) -> int:
    for s in (sys.stdout, sys.stderr):   # a piped Windows console is cp1252: never crash on a glyph
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    args = build_parser().parse_args(argv)
    color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    paint = _paint(color)
    reports, worst, failed, checked = [], 99, False, 0
    started = time.perf_counter()
    if not args.json:
        print(paint(f" provenance v{__version__}", "1;36") + "\n")
    for spec in args.packages:
        try:
            rel = registry.fetch(spec)
        except (registry.NotFound, net.FetchError) as e:
            failed = True
            if args.json:
                reports.append({"spec": spec, "error": str(e)})
            else:
                print(paint(f" {spec}", "1") + f"\n   {paint('? NOT CHECKED', '33')}  {e}\n")
            continue
        src, tried = source.locate(rel, args.repo, args.ref)
        rep = compare.compare(rel, src, tried)
        checked += 1
        worst = min([worst] + [compare.RANK[f.severity] for f in rep.findings])
        if args.json:
            reports.append(rep.to_dict())
        else:
            print(render(rep, args.min_severity, paint))
    if args.json:
        print(json.dumps({"version": __version__, "packages": reports}, indent=2))
    else:
        print(paint(f" {len(args.packages)} package(s) in {time.perf_counter() - started:.1f}s", "2"))
    if worst <= compare.RANK[args.fail_on]:
        return 1
    return 2 if failed and not checked else 0
