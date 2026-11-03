"""The other side: the repository at the commit (or tag) a release claims to come from."""

from __future__ import annotations

import re
from dataclasses import dataclass

from . import net
from .registry import Release

TEXT_LIMIT = 4 << 20


@dataclass
class Source:
    repo: str
    ref: str
    how: str                    # why this ref: attestation, gitHead, tag
    files: dict[str, bytes]     # whole repository, path -> bytes


def snapshot(repo: str, ref: str) -> dict[str, bytes]:
    data = net.get(f"{net.CODELOAD}/{repo}/tar.gz/{ref}")
    return {p: b for p, b in net.untar(data).items() if len(b) <= TEXT_LIMIT}


def _with_listed_tags(repo: str, version: str, refs: list[tuple[str, str]]):
    """The candidate refs, then any tag the repository lists whose version digits match (one API call, only if needed)."""
    yield from refs
    digits = re.sub(r"\D", "", version)
    try:
        listed = net.get_json(f"{net.GITHUB_API}/repos/{repo}/tags?per_page=100")
    except (net.FetchError, ValueError):
        return
    tried = {r for r, _ in refs}
    for t in listed if isinstance(listed, list) else []:
        name = t.get("name", "")
        if name not in tried and re.sub(r"\D", "", name).endswith(digits) and version.split(".")[0] in name:
            yield name, "release tag (from the repository's tag list)"


def locate(rel: Release, repo: str | None = None, ref: str | None = None) -> tuple[Source | None, list[str]]:
    """The source snapshot for a release, and what was tried."""
    repo = repo or rel.repo
    tried: list[str] = []
    if not repo:
        return None, ["the package names no GitHub repository"]
    refs: list[tuple[str, str]] = []
    if ref:
        refs.append((ref, "given on the command line"))
    if rel.commit:
        refs.append((rel.commit, rel.commit_source or "registry"))
    refs += [(t, "release tag") for t in rel.tags]
    for r, how in _with_listed_tags(repo, rel.version, refs):
        try:
            return Source(repo, r, how, snapshot(repo, r)), tried
        except net.FetchError as e:
            tried.append(f"{repo}@{r}: {e.status or e}")
            if e.status not in (404, 422):
                break
    return None, tried
