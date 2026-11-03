"""What was published: the files of a release on npm or PyPI, and every clue to the commit it was built
from (a signed build attestation, the gitHead npm records, or the release's tag)."""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field

from . import net


class NotFound(Exception):
    pass


@dataclass
class Release:
    ecosystem: str                  # npm | pypi
    name: str
    version: str
    files: dict[str, bytes]         # path inside the package -> bytes
    artifact: str                   # what was downloaded (tarball / sdist / wheel name)
    repo: str | None = None         # owner/name on GitHub
    directory: str = ""             # the package's folder inside a monorepo
    commit: str | None = None       # the exact commit, when the registry knows it
    commit_source: str | None = None
    tags: list[str] = field(default_factory=list)
    attested: bool = False


GITHUB = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:[/#?].*)?$", re.I)


def github_repo(url: str | None) -> str | None:
    if not url:
        return None
    url = url.strip()
    if re.fullmatch(r"(?:github:)?[\w.-]+/[\w.-]+", url):
        return url.split(":", 1)[-1]
    m = GITHUB.search(url)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _tags(name: str, version: str) -> list[str]:
    short = name.rsplit("/", 1)[-1]
    out = [f"v{version}", version, f"{name}@{version}", f"{short}@{version}", f"{short}-v{version}",
           f"{short}-{version}", f"release-{version}", f"release/{version}", f"{short}/v{version}",
           "rel_" + version.replace(".", "_"), f"{short}-v{version}".lower()]
    return list(dict.fromkeys(out))


def _attested_commit(name: str, version: str) -> tuple[str | None, str | None]:
    """(commit, repo) from npm's SLSA provenance attestation, if the release has one."""
    try:
        doc = net.get_json(f"{net.NPM}/-/npm/v1/attestations/{urllib.parse.quote(name, safe='@')}@{version}")
    except (net.FetchError, ValueError):
        return None, None
    for a in doc.get("attestations", []):
        if "slsa.dev/provenance" not in a.get("predicateType", ""):
            continue
        try:
            st = json.loads(base64.b64decode(a["bundle"]["dsseEnvelope"]["payload"]))
            deps = st["predicate"]["buildDefinition"].get("resolvedDependencies") or []
        except (KeyError, ValueError, TypeError):
            continue
        for d in deps:
            commit = (d.get("digest") or {}).get("gitCommit")
            if commit:
                return commit, github_repo(d.get("uri", "").split("@", 1)[0])
    return None, None


def npm(name: str, version: str | None = None) -> Release:
    quoted = urllib.parse.quote(name, safe="@")
    try:
        doc = net.get_json(f"{net.NPM}/{quoted}")
    except net.FetchError as e:
        raise NotFound(f"npm package {name} not found ({e.status})") from None
    version = version or (doc.get("dist-tags") or {}).get("latest")
    meta = (doc.get("versions") or {}).get(version)
    if not meta:
        if version in (doc.get("time") or {}):
            raise NotFound(f"{name}@{version} was published and then removed from npm")
        raise NotFound(f"{name}@{version} is not on npm")
    tarball = meta["dist"]["tarball"]
    files = net.untar(net.get(tarball))
    repo_field = meta.get("repository") or doc.get("repository") or {}
    if isinstance(repo_field, str):
        repo_field = {"url": repo_field}
    rel = Release("npm", name, version, files, tarball.rsplit("/", 1)[-1], github_repo(repo_field.get("url")),
                  (repo_field.get("directory") or "").strip("/"), tags=_tags(name, version))
    if (meta.get("dist") or {}).get("attestations"):
        commit, repo = _attested_commit(name, version)
        if commit:
            rel.commit, rel.commit_source, rel.attested = commit, "signed build provenance (SLSA)", True
            rel.repo = repo or rel.repo
    if not rel.commit and re.fullmatch(r"[0-9a-f]{40}", meta.get("gitHead") or ""):
        rel.commit, rel.commit_source = meta["gitHead"], "gitHead recorded by npm at publish time"
    return rel


def pypi(name: str, version: str | None = None) -> Release:
    try:
        doc = net.get_json(f"{net.PYPI}/pypi/{name}/{version}/json" if version else f"{net.PYPI}/pypi/{name}/json")
    except net.FetchError as e:
        raise NotFound(f"PyPI project {name}{'==' + version if version else ''} not found ({e.status})") from None
    info = doc["info"]
    version = info["version"]
    urls = doc.get("urls") or []
    if not urls:
        raise NotFound(f"{name}=={version} has no files on PyPI (yanked or removed)")
    sdist = next((u for u in urls if u["packagetype"] == "sdist"), None)
    wheel = next((u for u in urls if u["filename"].endswith("-none-any.whl")), None) or \
        next((u for u in urls if u["packagetype"] == "bdist_wheel"), None)
    pick = sdist or wheel
    data = net.get(pick["url"])
    files = net.untar(data) if pick["filename"].endswith((".tar.gz", ".tgz")) else net.unzip(data)
    repo = None
    links = dict(info.get("project_urls") or {})
    for key in sorted(links, key=lambda k: (not re.search(r"source|code|repo|github", k, re.I), k)):
        repo = github_repo(links[key])
        if repo:
            break
    repo = repo or github_repo(info.get("home_page"))
    return Release("pypi", info["name"], version, files, pick["filename"], repo, tags=_tags(info["name"], version))


def parse_spec(spec: str) -> tuple[str, str, str | None]:
    """'npm:react@18.3.1', 'pypi:requests==2.32.3', 'left-pad' -> (ecosystem, name, version)"""
    eco = "npm"
    if ":" in spec.split("@", 1)[0] or spec.startswith(("npm:", "pypi:", "pip:")):
        eco, spec = spec.split(":", 1)
        eco = "pypi" if eco in ("pypi", "pip") else eco
    if eco == "pypi":
        name, _, ver = spec.partition("==")
        return eco, name, ver or None
    if spec.startswith("@"):
        name, _, ver = spec[1:].partition("@")
        return eco, "@" + name, ver or None
    name, _, ver = spec.partition("@")
    return eco, name, ver or None


def fetch(spec: str) -> Release:
    eco, name, version = parse_spec(spec)
    if eco == "npm":
        return npm(name, version)
    if eco == "pypi":
        return pypi(name, version)
    raise NotFound(f"unknown ecosystem {eco!r} (use npm: or pypi:)")
