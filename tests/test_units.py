"""The parts on their own: capabilities, tokens, source maps, specs, and the command line."""

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fakeworld import World  # noqa: E402
from provenance import sourcemap  # noqa: E402
from provenance.capabilities import capabilities, risk, tokens  # noqa: E402
from provenance.registry import github_repo, parse_spec  # noqa: E402


class Capabilities(unittest.TestCase):
    def test_javascript(self):
        caps = capabilities("const cp = require('node:child_process'); import x from '@scope/pkg/sub';"
                            "cp.execSync('ls'); fetch('https://api.stats-collector.io/v1'); process.env.NPM_TOKEN;"
                            "eval(Buffer.from(s, 'base64').toString())", "a.js")
        for c in [("module", "child_process"), ("module", "@scope/pkg"), ("exec", "runs commands"), ("net", "makes web requests"),
                  ("host", "api.stats-collector.io"), ("env", "NPM_TOKEN"), ("eval", "eval/new Function"),
                  ("decode", "decodes base64/hex/compressed data")]:
            self.assertIn(c, caps)

    def test_python(self):
        caps = capabilities("import os, subprocess\nfrom base64 import b64decode\nexec(b64decode(blob))\n"
                            "token = os.environ['PYPI_TOKEN']\nopen(os.path.expanduser('~/.ssh/id_rsa'))\n", "x.py")
        for c in [("module", "subprocess"), ("eval", "exec/eval"), ("env", "PYPI_TOKEN"), ("sensitive", "SSH keys"), ("exec", "runs commands")]:
            self.assertIn(c, caps)

    def test_ordinary_code_has_no_risk(self):
        self.assertIsNone(risk(capabilities("export const add = (a, b) => a + b;", "a.js"), False))
        self.assertIsNone(risk(capabilities("Function('return this')()", "a.js"), False))   # the usual global lookup
        self.assertIsNone(risk({("host", "www.w3.org"), ("host", "foo.com")}, False))

    def test_risk_levels(self):
        self.assertEqual(risk({("exec", "x"), ("host", "203.0.113.9")}, True)[0], "critical")
        self.assertEqual(risk({("env", "AWS_SECRET_ACCESS_KEY"), ("net", "x")}, False)[0], "critical")
        self.assertEqual(risk({("obfuscated", "x")}, True)[0], "high")
        self.assertEqual(risk({("host", "cdn.tracker.io")}, True)[0], "low")
        self.assertEqual(risk({("host", "cdn.tracker.io")}, False)[0], "medium")

    def test_tokens_survive_builds(self):
        a = tokens("import { formatError as _formatError13 } from './err'; /* #__PURE__ */ go(`a ${b} c`)")
        self.assertTrue({"formatError", "err", "go"} <= a)
        self.assertNotIn("PURE", a)
        self.assertNotIn("formatError13", a)


class SourceMaps(unittest.TestCase):
    def test_vlq(self):
        self.assertEqual(sourcemap.vlq("AAAA"), [0, 0, 0, 0])
        self.assertEqual(sourcemap.vlq("AACA"), [0, 0, 1, 0])
        self.assertEqual(sourcemap.vlq("gBAAgB"), [16, 0, 0, 16])
        self.assertEqual(sourcemap.vlq("D"), [-1])

    def test_unmapped_text(self):
        m = {"mappings": "AAAA;;AACA,K"}                         # line 3: mapped from column 0, unmapped from column 5
        gen = "mapped line\ninjected();\nab ccccc"
        self.assertEqual(sourcemap.unmapped_text(gen, m), "injected();\nccc")

    def test_source_paths(self):
        m = {"sources": ["../src/a.ts", "webpack://pkg/./src/b.ts", "node_modules/x/y.js"], "sourcesContent": ["A", "B"], "mappings": ""}
        self.assertEqual(sourcemap.sources(m, "dist/index.js"), [("src/a.ts", "A"), ("src/b.ts", "B"), ("dist/node_modules/x/y.js", None)])


class Specs(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(parse_spec("left-pad"), ("npm", "left-pad", None))
        self.assertEqual(parse_spec("npm:react@18.3.1"), ("npm", "react", "18.3.1"))
        self.assertEqual(parse_spec("@types/node@20.1.0"), ("npm", "@types/node", "20.1.0"))
        self.assertEqual(parse_spec("pypi:requests==2.32.3"), ("pypi", "requests", "2.32.3"))
        self.assertEqual(parse_spec("pip:flask"), ("pypi", "flask", None))

    def test_github_urls(self):
        for url in ["git+https://github.com/vitejs/vite.git", "https://github.com/vitejs/vite/tree/main/packages/vite",
                    "git@github.com:vitejs/vite.git", "github:vitejs/vite", "vitejs/vite"]:
            self.assertEqual(github_repo(url), "vitejs/vite", url)
        self.assertIsNone(github_repo("https://gitlab.com/a/b"))


class CommandLine(unittest.TestCase):
    def run_cli(self, world, *args):
        env = {**os.environ, "PROVENANCE_NPM": world.url, "PROVENANCE_PYPI": world.url, "PROVENANCE_CODELOAD": world.url,
               "PROVENANCE_GITHUB_API": world.url, "PYTHONIOENCODING": "utf-8"}
        return subprocess.run([sys.executable, "-m", "provenance", *args, "--no-color"], cwd=ROOT, env=env,
                              capture_output=True, text=True, encoding="utf-8")

    def test_exit_codes_and_json(self):
        w = World()
        self.addCleanup(w.close)
        lib = "module.exports = 1;\n"
        w.repo("acme/pkg", "v1.0.0", {"index.js": lib})
        w.npm("good", "1.0.0", {"index.js": lib})
        w.npm("bad", "1.0.0", {"index.js": lib, "package.json": json.dumps({"name": "bad", "scripts": {"postinstall": "node x.js"}})})
        ok = self.run_cli(w, "good")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertIn("MATCHES", ok.stdout)
        bad = self.run_cli(w, "good", "bad", "--json")
        self.assertEqual(bad.returncode, 1, bad.stderr)
        report = json.loads(bad.stdout)
        self.assertEqual([p["verdict"] for p in report["packages"]], ["matches", "differs"])
        missing = self.run_cli(w, "nope")
        self.assertEqual(missing.returncode, 2)
        self.assertIn("NOT CHECKED", missing.stdout)


if __name__ == "__main__":
    unittest.main()
