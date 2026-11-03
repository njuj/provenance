"""HTTP and archives: fetching registry metadata, package files and source snapshots, and unpacking
them in memory. Endpoints can be pointed elsewhere (a mirror, or the test suite's local server)."""

from __future__ import annotations

import gzip
import io
import json
import os
import tarfile
import urllib.error
import urllib.request
import zipfile

from . import __version__

NPM = os.environ.get("PROVENANCE_NPM", "https://registry.npmjs.org")
PYPI = os.environ.get("PROVENANCE_PYPI", "https://pypi.org")
CODELOAD = os.environ.get("PROVENANCE_CODELOAD", "https://codeload.github.com")
GITHUB_API = os.environ.get("PROVENANCE_GITHUB_API", "https://api.github.com")

MAX_DOWNLOAD = 200 << 20
MAX_FILE = 20 << 20


class FetchError(Exception):
    def __init__(self, url: str, status: int | None, msg: str = ""):
        super().__init__(f"{url}: {status or ''} {msg}".strip())
        self.url, self.status = url, status


_cache: dict[str, bytes] = {}


def get(url: str, *, accept: str = "*/*", limit: int = MAX_DOWNLOAD) -> bytes:
    if url in _cache:
        return _cache[url]
    headers = {"User-Agent": f"provenance/{__version__} (+https://github.com/njuj/provenance)", "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith(GITHUB_API):
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            data = r.read(limit + 1)
    except urllib.error.HTTPError as e:
        raise FetchError(url, e.code, e.reason) from None
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        raise FetchError(url, None, str(getattr(e, "reason", e))) from None
    if len(data) > limit:
        raise FetchError(url, None, f"larger than {limit >> 20} MB")
    _cache[url] = data
    return data


def get_json(url: str):
    return json.loads(get(url, accept="application/json"))


def untar(data: bytes, strip: int = 1) -> dict[str, bytes]:
    """{path: bytes} of the regular files in a .tar.gz, the first `strip` path components removed."""
    out: dict[str, bytes] = {}
    raw = gzip.decompress(data) if data[:2] == b"\x1f\x8b" else data
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as tf:
        for m in tf:
            if not m.isfile() or m.size > MAX_FILE:
                continue
            parts = m.name.replace("\\", "/").lstrip("./").split("/")[strip:]
            if not parts or any(p in ("", "..") for p in parts):
                continue
            f = tf.extractfile(m)
            if f is not None:
                out["/".join(parts)] = f.read()
    return out


def unzip(data: bytes) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            if info.is_dir() or info.file_size > MAX_FILE or ".." in info.filename.split("/"):
                continue
            out[info.filename] = z.read(info)
    return out
