"""Published files against source files. Every published file ends up in one of five piles:

  identical   byte for byte the file in the repository (line endings aside)
  traced      built, and its source map leads back to the repository's own sources
  built       built output with nothing to trace it by: checked for capabilities its source never had
  changed     the repository has the file, but the published copy differs
  extra       code that exists only in the package

and what matters is reported: install scripts and dependencies that appear at publish time, and code
that can do things (run commands, decode and evaluate, read secrets, contact hosts) nothing in the
repository can do."""

from __future__ import annotations

import base64
import difflib
import json
import posixpath
import re
from dataclasses import dataclass, field

from . import sourcemap
from .capabilities import CODE_EXT, JS_EXT, PY_EXT, STRONG, capabilities, describe, risk, tokens
from .registry import Release
from .source import Source

SEVERITIES = ["critical", "high", "medium", "low", "info"]
RANK = {s: i for i, s in enumerate(SEVERITIES)}
INSTALL_HOOKS = ("preinstall", "install", "postinstall", "preuninstall", "uninstall", "postuninstall")
BUILT_DIRS = ("dist/", "lib/", "build/", "esm/", "cjs/", "umd/", "es/", "out/", "bundle/", "types/", "typings/",
              "module/", "browser/", "node/", "_cjs/", "_esm/", "_types/", "compiled/")
META = re.compile(r"(^|/)(readme|license|licence|copying|notice|changelog|changes|history|authors|contributors|"
                  r"security|code_of_conduct)(\.[\w.]+)?$|(^|/)PKG-INFO$|\.dist-info/|\.egg-info/|(^|/)setup\.cfg$|"
                  r"(^|/)\.npmignore$|(^|/)\.gitignore$", re.I)
GENERATED_PY = re.compile(r"(^|/)_?[\w-]*version(_info)?\.py$")


@dataclass
class Finding:
    severity: str
    kind: str
    path: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return self.__dict__.copy()


@dataclass
class Report:
    release: Release
    source: Source | None
    tried: list[str]
    piles: dict[str, list[str]] = field(default_factory=lambda: {k: [] for k in ("identical", "traced", "built", "changed", "extra", "metadata")})
    findings: list[Finding] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.source is None:
            return "unverifiable"
        if any(RANK[f.severity] <= RANK["high"] for f in self.findings):
            return "differs"
        code = [p for k in ("built", "changed", "extra") for p in self.piles[k] if p.endswith(CODE_EXT)]
        return "matches" if not code else "consistent"

    def to_dict(self) -> dict:
        r = self.release
        return {"ecosystem": r.ecosystem, "name": r.name, "version": r.version, "artifact": r.artifact,
                "repo": self.source.repo if self.source else r.repo,
                "ref": self.source.ref if self.source else None, "ref_from": self.source.how if self.source else None,
                "attested": r.attested, "verdict": self.verdict, "tried": self.tried,
                "counts": {k: len(v) for k, v in self.piles.items()},
                "findings": [f.to_dict() for f in sorted(self.findings, key=lambda f: RANK[f.severity])]}


def _text(b: bytes) -> str | None:
    if b"\0" in b[:8192]:
        return None
    return b.decode("utf-8", "replace")


def _norm(b: bytes) -> bytes:
    return b.replace(b"\r\n", b"\n").rstrip()


class Index:
    """Find the repository file a published path corresponds to (same path, or the longest matching suffix)."""

    def __init__(self, files: dict[str, bytes], directory: str):
        self.files = files
        self.directory = directory.strip("/")
        self.by_name: dict[str, list[str]] = {}
        for p in files:
            self.by_name.setdefault(posixpath.basename(p), []).append(p)

    def match(self, path: str) -> str | None:
        if self.directory and f"{self.directory}/{path}" in self.files:
            return f"{self.directory}/{path}"
        if not self.directory and path in self.files:
            return path
        cands = [p for p in self.by_name.get(posixpath.basename(path), []) if p == path or p.endswith("/" + path)]
        if not cands:
            parts = path.split("/")
            for k in range(1, len(parts) - 1):          # drop leading folders: dist/foo/x.py vs src/foo/x.py
                tail = "/".join(parts[k:])
                cands = [p for p in self.by_name.get(parts[-1], []) if p.endswith("/" + tail)]
                if cands:
                    break
        if not cands:
            return None
        inside = [p for p in cands if self.directory and p.startswith(self.directory + "/")]
        pool = inside or cands
        return min(pool, key=lambda p: (len(p), p)) if len(pool) <= 3 else (inside[0] if len(inside) == 1 else None)

    def stem_exists(self, path: str) -> bool:
        """dist/x.js and a src/x.ts somewhere: built output."""
        stem = posixpath.basename(path).split(".", 1)[0]
        for name in self.by_name:
            if name.split(".", 1)[0] == stem and name.endswith((".ts", ".tsx", ".mts", ".cts", ".jsx", ".js", ".mjs", ".vue", ".svelte", ".coffee", ".py", ".pyx")):
                return True
        return False


def _built(path: str, idx: Index) -> bool:
    p = path.lower()
    return (p.startswith(BUILT_DIRS) or "/dist/" in p or p.endswith((".d.ts", ".d.mts", ".d.cts", ".map", ".min.js", ".min.mjs"))
            or (p.endswith(JS_EXT) and idx.stem_exists(path)))


def _diff(old: str, new: str) -> tuple[list[str], int, int]:
    added, removed = [], 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, len(added), removed


def _inline_map(text: str) -> dict | None:
    m = re.search(r"//[#@] sourceMappingURL=data:application/json(?:;charset=[\w-]+)?;base64,([A-Za-z0-9+/=]+)\s*$", text)
    if not m:
        return None
    try:
        return sourcemap.load(base64.b64decode(m.group(1)))
    except ValueError:
        return None


def compare(rel: Release, src: Source | None, tried: list[str]) -> Report:
    rep = Report(rel, src, tried)
    if src is None:
        rep.findings.append(Finding("medium", "no-source", "", "No source to compare with",
                                    "the package could not be matched to a repository snapshot: " + ("; ".join(tried[:4]) or "no repository")))
        return rep
    directory = rel.directory or _package_dir(rel, src.files)
    idx = Index(src.files, directory)
    src_caps: set[tuple[str, str]] = set()
    src_tokens: set[str] = set()
    for p, b in src.files.items():
        if p.endswith(CODE_EXT + (".json", ".md", ".html", ".yml", ".yaml", ".toml", ".cfg")):
            t = _text(b)
            if t is not None:
                src_caps |= capabilities(t, p)
                if p.endswith(CODE_EXT):
                    src_tokens |= tokens(t)
    version_tokens = {rel.version, f"v{rel.version}"}

    def flag(path: str, new: set, built: bool, how: str, evidence: list[str] | None = None, floor: str | None = None):
        r = risk(new, built)
        if r is None and floor is None:
            return
        sev, why = r or (floor, "")
        if floor and RANK[floor] < RANK[sev]:
            sev = floor
        rep.findings.append(Finding(sev, how, path, f"{path}: {why}" if why else path,
                                    f"{_HOW[how]}. New compared with the repository: {describe(new) or 'nothing it can do differently'}",
                                    evidence or []))

    for path, data in sorted(rel.files.items()):
        if rel.ecosystem == "npm" and path == "package.json":
            _manifest(rep, data, idx)
            continue
        twin = idx.match(path)
        if twin is not None and _norm(src.files[twin]) == _norm(data):
            rep.piles["identical"].append(path)
            continue
        if META.search(path) or path.endswith((".md", ".txt", ".rst")):
            rep.piles["metadata"].append(path)
            continue
        text = _text(data)
        is_code = path.endswith(CODE_EXT)
        built = _built(path, idx)
        if is_code and text is not None and rel.ecosystem == "pypi" and GENERATED_PY.search(path) and _version_only(text):
            rep.piles["built"].append(path)                      # _version.py written by setuptools-scm / hatch-vcs
            continue
        same_place = twin is not None and (twin == path or twin.endswith("/" + path))
        if twin is not None and (same_place or not built):
            rep.piles["changed"].append(path)
            if text is None or not is_code:
                continue
            old = _text(src.files[twin]) or ""
            added, n_add, n_del = _diff(old, text)
            # code that only lost lines, or whose added lines only reuse names and strings the repository already
            # has (comments stripped, a version stamped in, types removed, reformatted), says nothing new
            fresh = tokens("\n".join(added)) - src_tokens - version_tokens
            caps = capabilities("\n".join(added), path)
            bundled = (n_add > 200 and n_add > 3 * max(1, len(old.splitlines()))) or len(text) > 20 * max(1, len(old))
            if bundled:                                           # a source entry point published as a bundle: judge it as built
                new = caps - capabilities(old, twin) - src_caps
            else:
                new = {c for c in caps - capabilities(old, twin) if c[0] in STRONG or c not in src_caps}
            setup = posixpath.basename(path) in ("setup.py", "conftest.py")
            if not new and not fresh:
                continue
            r = risk(new, bundled)
            sev = r[0] if r else ("info" if bundled or not fresh else "low")
            if setup and new and RANK[sev] > RANK["high"]:
                sev = "high"                                      # setup.py runs at install time
            rep.findings.append(Finding(sev, "changed", path,
                                        f"{path}: {r[1]}" if r else f"{path} differs from {twin} in the repository",
                                        f"{_HOW['changed']} (+{n_add} −{n_del} lines)."
                                        + (f" New: {describe(new)}" if new else f" New names or strings: {', '.join(sorted(fresh)[:8])}"),
                                        [a.strip()[:200] for a in added if a.strip()][:6]))
            continue
        if not is_code or text is None:
            if path.endswith(".map") or path.endswith(".json"):
                rep.piles["built" if built else "metadata"].append(path)
            else:
                rep.piles["metadata"].append(path)
            continue
        caps = capabilities(text, path)
        m = _inline_map(text)
        if m is None and f"{path}.map" in rel.files:
            m = sourcemap.load(rel.files[f"{path}.map"])
        if built and m is not None:
            before = len(rep.findings)
            if _trace(rep, path, text, m, idx, src_caps, src_tokens):
                rep.piles["traced"].append(path)
                continue
            if len(rep.findings) > before:                       # already explained through the map
                rep.piles["built"].append(path)
                continue
        rep.piles["built" if built else "extra"].append(path)
        aside = bool(re.search(r"(^|/)(docs?|examples?|tests?|__tests__|spec|benchmarks?|fixtures?)/", path))
        flag(path, caps - src_caps, built or aside, "built" if built else "extra",
             floor=None if built else ("high" if path.endswith(PY_EXT) and rel.ecosystem == "pypi" else "low"))
    return rep


_HOW = {
    "changed": "The repository has this file, but the published copy differs",
    "built": "Built output",
    "extra": "This code exists only in the package, not in the repository",
    "unmapped": "Code in the built file that its source map ties to no source",
    "map-source": "The source map embeds a source that differs from the repository's",
}


def _version_only(text: str) -> bool:
    caps = capabilities(text, "x.py")
    return "version" in text and not any(k in STRONG or k == "host" for k, _ in caps) and len(text) < 4000


def _package_dir(rel: Release, files: dict[str, bytes]) -> str:
    """The folder of a monorepo whose manifest names this package."""
    names = ("package.json",) if rel.ecosystem == "npm" else ("pyproject.toml", "setup.py", "setup.cfg")
    hits = []
    for p, b in files.items():
        if posixpath.basename(p) not in names or "node_modules/" in p:
            continue
        t = _text(b) or ""
        if rel.ecosystem == "npm":
            try:
                if json.loads(t).get("name") == rel.name:
                    hits.append(posixpath.dirname(p))
            except (ValueError, AttributeError):
                continue
        elif re.search(r"""name\s*[=:]\s*["']?%s["']?\s*$""" % re.escape(rel.name), t, re.M | re.I):
            hits.append(posixpath.dirname(p))
    return min(hits, key=len) if hits else ""


def _trace(rep: Report, path: str, text: str, m: dict, idx: Index, src_caps: set, src_tokens: set) -> bool:
    """Check a built file through its source map; True when it traces back cleanly."""
    own, ok, seen = 0, True, set()
    for spath, content in sourcemap.sources(m, path):
        if ("node_modules/" in spath or spath.startswith(("webpack/", "(webpack)", "\0")) or content is None
                or not spath.endswith(CODE_EXT) or spath in seen):
            continue
        seen.add(spath)
        twin = idx.match(spath)
        if twin is None:
            continue
        own += 1
        if _norm(content.encode()) != _norm(rep.source.files[twin]):
            old = _text(rep.source.files[twin]) or ""
            added, n_add, n_del = _diff(old, content)
            fresh = tokens("\n".join(added)) - src_tokens - {rep.release.version}
            new = {c for c in capabilities("\n".join(added), spath) - capabilities(old, twin) if c[0] in STRONG or c not in src_caps}
            r = risk(new, False)
            if not fresh and r is None:
                continue                                         # the same code with its types stripped or reformatted
            rep.findings.append(Finding(r[0] if r else "medium", "map-source", path,
                                        f"{path} was built from a {spath} that is not the repository's",
                                        f"{_HOW['map-source']} (+{n_add} −{n_del} lines)" + (f": {r[1]}" if r else
                                        f". New names or strings: {', '.join(sorted(fresh)[:8])}"),
                                        [a.strip()[:200] for a in added if a.strip()][:6]))
            ok = False
    loose = sourcemap.unmapped_text(text, m)
    new = capabilities(loose, path) - src_caps
    r = risk(new, False)
    if r and RANK[r[0]] <= RANK["medium"]:
        rep.findings.append(Finding("critical" if RANK[r[0]] <= RANK["high"] else "high", "unmapped", path,
                                    f"{path}: {r[1]}, in code no source line produced",
                                    f"{_HOW['unmapped']}. {describe(new)}", _snippets(loose, new)))
        ok = False
    return ok and own > 0


def _snippets(text: str, caps: set) -> list[str]:
    keys = [v for k, v in caps if k in ("host", "env", "module")] + ["eval(", "Function(", "exec", "child_process", "base64"]
    out = []
    for line in text.splitlines():
        if any(k in line for k in keys) and line.strip():
            out.append(line.strip()[:200])
        if len(out) >= 4:
            break
    return out


def _build_files(files: dict[str, bytes]) -> str:
    """Text of the files release tooling reads: manifests, workspace configs, build and publish scripts."""
    out = []
    for p, b in files.items():
        name = posixpath.basename(p)
        if (name in ("package.json", "pnpm-workspace.yaml", "lerna.json", "nx.json", "turbo.json")
                or re.search(r"(^|/)(scripts?|tools|build|release|npm)/|publish|release|build\.", p)):
            t = _text(b)
            if t:
                out.append(t)
    return "\n".join(out)


def _manifest(rep: Report, data: bytes, idx: Index) -> None:
    """The published package.json against the repository's: install scripts and dependencies."""
    try:
        pub = json.loads(data)
    except ValueError:
        return
    twin = idx.match("package.json")
    try:
        src = json.loads(rep.source.files[twin]) if twin else {}
    except ValueError:
        src = {}
    rep.piles["identical" if twin and _norm(rep.source.files[twin]) == _norm(data) else "metadata"].append("package.json")
    ps, ss = pub.get("scripts") or {}, src.get("scripts") or {}
    for hook in INSTALL_HOOKS:
        if hook not in ps:
            continue
        if ps[hook] != ss.get(hook):
            rep.findings.append(Finding("critical", "install-script", "package.json", f"`{hook}` script added at publish time",
                                        f"every `npm install` runs: {ps[hook]}" + (f" (the repository has: {ss[hook]})" if hook in ss else
                                                                                  " (the repository has no such script)"),
                                        [ps[hook][:200]]))
        else:
            rep.findings.append(Finding("info", "install-script", "package.json", f"runs `{hook}` on install",
                                        f"{ps[hook]} (the same in the repository)"))
    for key in ("dependencies", "optionalDependencies"):
        pd, sd = pub.get(key) or {}, src.get(key) or {}
        if not twin:
            continue
        added = [d for d in pd if d not in sd and d not in (src.get("devDependencies") or {}) and d not in (src.get("peerDependencies") or {})]
        if added:
            kind = "optional dependenc" if key == "optionalDependencies" else "dependenc"
            blob = _build_files(rep.source.files)
            # named by the release tooling, or pinned to this very version (per-platform binary packages)
            known = [d for d in added if d in blob or str(pd[d]).lstrip("=v") == rep.release.version]
            if len(known) == len(added):                      # filled in by the repository's own release tooling
                rep.findings.append(Finding("low", "dependency", "package.json",
                                            f"{len(added)} {kind}{'ies' if len(added) > 1 else 'y'} filled in at publish time",
                                            "not in the package's own package.json, but named by the repository's build or workspace files: "
                                            + ", ".join(f"{d}@{pd[d]}" for d in added[:8])))
                continue
            added = [d for d in added if d not in known]
            rep.findings.append(Finding("high", "dependency", "package.json",
                                        f"{len(added)} {kind}{'ies' if len(added) > 1 else 'y'} added at publish time",
                                        f"in the published package.json but not the repository's: {', '.join(f'{d}@{pd[d]}' for d in added[:8])}",
                                        [f"{d}: {pd[d]}" for d in added[:8]]))
