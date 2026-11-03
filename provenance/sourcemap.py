"""Source maps tie every piece of a built file to the source line it came from. That makes two checks
possible without rebuilding anything: the sources embedded in the map must be the repository's
sources, and code in the build that maps to no source at all is code the build did not get from the
repository."""

from __future__ import annotations

import json
import posixpath

B64 = {c: i for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")}


def vlq(segment: str) -> list[int]:
    out, value, shift = [], 0, 0
    for ch in segment:
        d = B64.get(ch)
        if d is None:
            raise ValueError(f"bad VLQ character {ch!r}")
        value += (d & 31) << shift
        if d & 32:
            shift += 5
            continue
        out.append(-(value >> 1) if value & 1 else value >> 1)
        value, shift = 0, 0
    return out


def load(raw: bytes) -> dict | None:
    try:
        m = json.loads(raw.decode("utf-8", "replace").lstrip(")]}'\n"))
    except ValueError:
        return None
    if not isinstance(m, dict) or "mappings" not in m:
        return None
    if "sections" in m:                                  # indexed maps: not merged here
        return None
    return m


def sources(m: dict, map_path: str) -> list[tuple[str, str | None]]:
    """[(source path, embedded content or None)]; paths are only hints: they are matched by suffix later."""
    root = m.get("sourceRoot") or ""
    contents = m.get("sourcesContent") or []
    base = posixpath.dirname(map_path)
    out = []
    for i, s in enumerate(m.get("sources") or []):
        s = (s or "").split("?", 1)[0]
        if "://" in s:                                   # webpack://pkg/./src/a.ts, file:///home/ci/src/a.ts
            s = s.split("://", 1)[1]
            s = s.lstrip("/")
            if s.startswith(("./", "../")) is False and "/" in s and s.split("/", 1)[0] and not s.startswith("home"):
                s = s.split("/", 1)[1] if s.split("/", 1)[1].startswith((".", "src", "lib", "packages", "node_modules")) else s
        else:
            s = posixpath.join(base, root, s)
        s = posixpath.normpath(s).lstrip("./")
        while s.startswith("../"):
            s = s[3:]
        out.append((s, contents[i] if i < len(contents) else None))
    return out


def unmapped_text(generated: str, m: dict) -> str:
    """The parts of the generated code no mapping segment points back to a source for."""
    lines = generated.split("\n")
    pieces = []
    for li, group in enumerate(m.get("mappings", "").split(";")):
        if li >= len(lines):
            break
        line = lines[li]
        segs = []
        col = 0
        for seg in group.split(","):
            if not seg:
                continue
            try:
                f = vlq(seg)
            except ValueError:
                return ""
            col += f[0]
            segs.append((col, len(f) >= 4))
        if not segs:
            pieces.append(line)
            continue
        if segs[0][0] > 0:
            pieces.append(line[:segs[0][0]])
        for k, (c, mapped) in enumerate(segs):
            end = segs[k + 1][0] if k + 1 < len(segs) else len(line)
            if not mapped:
                pieces.append(line[c:end])
    for line in lines[len(m.get("mappings", "").split(";")):]:
        pieces.append(line)
    return "\n".join(pieces)
