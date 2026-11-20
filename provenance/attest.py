"""Who built a release, from its signed attestation: the repository, commit and ref that a Sigstore
(Fulcio) certificate records for a trusted-publishing build. PyPI publishes these for every file
uploaded through Trusted Publishing (PEP 740); npm's SLSA provenance names the same facts.

The certificate is read, not verified: provenance takes the registry's word for the attestation
(PyPI and npm verify it at upload) and uses it to pick the right commit, and to catch a package whose
signed build came from a different repository than the one it advertises."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

# Fulcio certificate extensions (https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md)
FULCIO = {"1.3.6.1.4.1.57264.1.12": "repository", "1.3.6.1.4.1.57264.1.13": "commit",
          "1.3.6.1.4.1.57264.1.14": "ref", "1.3.6.1.4.1.57264.1.9": "workflow"}


@dataclass
class Build:
    repository: str | None = None      # owner/name on GitHub
    commit: str | None = None
    ref: str | None = None             # refs/tags/v1.2.3
    workflow: str | None = None        # the workflow file that ran the build
    source: str = ""


def _tlv(b: bytes, i: int) -> tuple[int, bytes, int]:
    if i + 2 > len(b):
        raise ValueError("truncated DER")
    tag, n = b[i], b[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if not 0 < k <= 4 or i + k > len(b):
            raise ValueError("bad DER length")
        n, i = int.from_bytes(b[i:i + k], "big"), i + k
    if i + n > len(b):
        raise ValueError("DER runs past its container")
    return tag, b[i:i + n], i + n


def _items(b: bytes) -> list[tuple[int, bytes]]:
    out, i = [], 0
    while i < len(b) and len(out) < 256:
        tag, val, i = _tlv(b, i)
        out.append((tag, val))
    return out


def oid(raw: bytes) -> str:
    if not raw:
        return ""
    parts, n = [raw[0] // 40, raw[0] % 40], 0
    for byte in raw[1:]:
        n = (n << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(n)
            n = 0
    return ".".join(map(str, parts))


def extensions(der: bytes) -> dict[str, str]:
    """The Fulcio extensions of a certificate, by name."""
    _, cert, _ = _tlv(der, 0)
    _, tbs, _ = _tlv(cert, 0)
    out: dict[str, str] = {}
    for tag, val in _items(tbs):
        if tag != 0xA3:                                   # [3] extensions
            continue
        _, seq, _ = _tlv(val, 0)
        for _, ext in _items(seq):
            parts = _items(ext)
            if len(parts) < 2 or parts[0][0] != 0x06 or oid(parts[0][1]) not in FULCIO:
                continue
            value = parts[-1][1]                          # OCTET STRING holding a DER UTF8String
            try:
                t, inner, _ = _tlv(value, 0)
                text = inner if t in (0x0C, 0x16, 0x13) else value
            except ValueError:
                text = value
            out[FULCIO[oid(parts[0][1])]] = text.decode("utf-8", "replace")
    return out


def from_certificate(der: bytes, source: str) -> Build:
    from .registry import github_repo
    ext = extensions(der)
    commit = ext.get("commit", "")
    return Build(github_repo(ext.get("repository")), commit if len(commit) == 40 else None, ext.get("ref"),
                 ext.get("workflow"), source)


def pypi_build(doc: dict) -> Build | None:
    """The build behind a file, from PyPI's integrity API answer (PEP 740 provenance)."""
    from .registry import github_repo
    for bundle in doc.get("attestation_bundles") or []:
        publisher = bundle.get("publisher") or {}
        for a in bundle.get("attestations") or []:
            try:
                der = base64.b64decode(a["verification_material"]["certificate"])
                b = from_certificate(der, "signed PyPI attestation (Trusted Publishing)")
            except (KeyError, ValueError, TypeError):
                continue
            b.repository = b.repository or github_repo(publisher.get("repository"))
            if b.commit:
                return b
        if publisher.get("kind") == "GitHub" and publisher.get("repository"):
            return Build(github_repo(publisher["repository"]), None, None, publisher.get("workflow"),
                         "PyPI Trusted Publishing")
    return None


def statement(envelope_b64: str) -> dict:
    return json.loads(base64.b64decode(envelope_b64))
