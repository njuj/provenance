"""A local stand-in for npm, PyPI, GitHub's codeload and its API, so every scenario runs offline and
exactly: the test decides what was published and what the repository holds."""

from __future__ import annotations

import base64
import gzip
import io
import json
import tarfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from provenance import net


def targz(files: dict[str, str | bytes], top: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path, data in files.items():
            raw = data.encode() if isinstance(data, str) else data
            info = tarfile.TarInfo(f"{top}/{path}")
            info.size = len(raw)
            tf.addfile(info, io.BytesIO(raw))
    return gzip.compress(buf.getvalue())


def wheel(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p, d in files.items():
            z.writestr(p, d)
    return buf.getvalue()


class World:
    def __init__(self):
        self.routes: dict[str, tuple[int, bytes]] = {}
        world = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                status, body = world.routes.get(self.path.split("?")[0] if "/tags" not in self.path else self.path.split("?")[0], (404, b"not found"))
                self.send_response(status)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.saved = (net.NPM, net.PYPI, net.CODELOAD, net.GITHUB_API)
        net.NPM = net.PYPI = net.CODELOAD = net.GITHUB_API = self.url
        net._cache.clear()

    def close(self):
        net.NPM, net.PYPI, net.CODELOAD, net.GITHUB_API = self.saved
        net._cache.clear()
        self.server.shutdown()
        self.server.server_close()

    # ── what a test sets up ────────────────────────────────────────────────
    def repo(self, repo: str, ref: str, files: dict[str, str]):
        self.routes[f"/{repo}/tar.gz/{ref}"] = (200, targz(files, f"{repo.split('/')[1]}-{ref[:12]}"))

    def npm(self, name: str, version: str, files: dict[str, str], *, repo: str | None = "acme/pkg", directory: str = "",
            git_head: str | None = None, attested_commit: str | None = None, removed: bool = False):
        tarball = f"{self.url}/{name}/-/{name.split('/')[-1]}-{version}.tgz"
        meta = {"name": name, "version": version, "dist": {"tarball": tarball}}
        if repo:
            meta["repository"] = {"type": "git", "url": f"git+https://github.com/{repo}.git", **({"directory": directory} if directory else {})}
        if git_head:
            meta["gitHead"] = git_head
        if attested_commit:
            meta["dist"]["attestations"] = {"url": "x", "provenance": {"predicateType": "https://slsa.dev/provenance/v1"}}
            statement = {"predicate": {"buildDefinition": {"resolvedDependencies": [
                {"uri": f"git+https://github.com/{repo}@refs/heads/main", "digest": {"gitCommit": attested_commit}}]}}}
            self.routes[f"/-/npm/v1/attestations/{name}@{version}"] = (200, json.dumps({"attestations": [
                {"predicateType": "https://slsa.dev/provenance/v1",
                 "bundle": {"dsseEnvelope": {"payload": base64.b64encode(json.dumps(statement).encode()).decode()}}}]}).encode())
        doc = {"name": name, "dist-tags": {"latest": version}, "versions": {} if removed else {version: meta},
               "time": {version: "2026-01-01T00:00:00Z"}}
        self.routes[f"/{name}"] = (200, json.dumps(doc).encode())
        self.routes[tarball[len(self.url):]] = (200, targz(files, "package"))

    def pypi(self, name: str, version: str, files: dict[str, str], *, repo: str = "acme/pylib", sdist: bool = True):
        fname = f"{name}-{version}.tar.gz" if sdist else f"{name}-{version}-py3-none-any.whl"
        data = targz(files, f"{name}-{version}") if sdist else wheel(files)
        doc = {"info": {"name": name, "version": version, "project_urls": {"Source": f"https://github.com/{repo}"}},
               "urls": [{"packagetype": "sdist" if sdist else "bdist_wheel", "filename": fname, "url": f"{self.url}/files/{fname}"}]}
        self.routes[f"/pypi/{name}/{version}/json"] = (200, json.dumps(doc).encode())
        self.routes[f"/pypi/{name}/json"] = (200, json.dumps(doc).encode())
        self.routes[f"/files/{fname}"] = (200, data)
