"""What a file can do, as far as reading it can tell: the modules it loads, the hosts it names, whether
it runs commands or evaluates strings, which secrets and sensitive paths it touches, whether it is
obfuscated. Minifiers keep all of these, which is what lets a build be checked against its source."""

from __future__ import annotations

import re

JS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".vue", ".svelte", ".coffee")
PY_EXT = (".py", ".pyw", ".pyi")
SH_EXT = (".sh", ".bash", ".ps1", ".bat", ".cmd")
CODE_EXT = JS_EXT + PY_EXT + SH_EXT

EXEC_MODULES = {"child_process", "subprocess", "os.system", "pty", "commands"}
NET_MODULES = {"http", "https", "net", "tls", "dgram", "dns", "socket", "urllib", "urllib.request", "requests",
               "httpx", "aiohttp", "http.client", "ftplib", "smtplib", "node-fetch", "axios", "undici", "ws"}
LOW_LEVEL = {"ctypes", "marshal", "ffi-napi", "vm", "worker_threads", "inspector", "cluster"}

COMMON_HOSTS = re.compile(r"(^|\.)(w3\.org|json-schema\.org|schema\.org|example\.(com|org|net)|localhost|github\.com|"
                          r"githubusercontent\.com|github\.io|npmjs\.(org|com)|nodejs\.org|mozilla\.org|ietf\.org|"
                          r"unicode\.org|opensource\.org|apache\.org|python\.org|pypi\.org|readthedocs\.(io|org)|"
                          r"wikipedia\.org|whatwg\.org|ecma-international\.org|creativecommons\.org|spdx\.org|"
                          r"microsoft\.com|google\.com|googleapis\.com|gstatic\.com|apple\.com|xml\.org|"
                          r"purl\.org|semver\.org|tc39\.es|mit-license\.org|gnu\.org|jsdelivr\.net|unpkg\.com|"
                          r"foo\.(com|org|bar)|bar\.(com|org)|baz\.com|[\w-]+\.(test|invalid|local|localhost|example))$", re.I)

SENSITIVE = [
    (re.compile(r"\.ssh[/\\]|id_rsa|id_ed25519|authorized_keys"), "SSH keys"),
    (re.compile(r"\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.docker[/\\]config\.json"), "registry or git credentials"),
    (re.compile(r"\.aws[/\\]credentials|\.azure[/\\]|gcloud[/\\]|\.kube[/\\]config"), "cloud credentials"),
    (re.compile(r"/etc/(passwd|shadow)|\.bash_history|\.zsh_history"), "system or shell history files"),
    (re.compile(r"Login Data|Network[/\\]Cookies|Local Storage[/\\]leveldb|cookies\.sqlite|logins\.json|key4\.db"), "browser credential stores"),
    (re.compile(r"Exodus[/\\]exodus\.wallet|Electrum[/\\]wallets|wallet\.dat|keystore[/\\]UTC--|"
                r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa"), "cryptocurrency wallets"),
    (re.compile(r"/dev/tcp/|nc -e |bash -i >&|powershell(\.exe)? .*-enc", re.I), "a reverse shell"),
    (re.compile(r"(curl|wget)\s[^\n'\"`]{0,120}\|\s*(ba)?sh"), "a download piped to a shell"),
]
SECRET_ENV = re.compile(r"TOKEN|SECRET|PASSWORD|PASSWD|PRIVATE|API_?KEY|ACCESS_KEY|CREDENTIAL|NPM_|AWS_|GITHUB_|GH_|"
                        r"PYPI|AZURE|GCP_|GOOGLE_APPLICATION|SLACK|DISCORD|WEBHOOK", re.I)

JS_MODULE = re.compile(r"""(?:require|import)\s*\(\s*['"]([^'"\n]+)['"]\s*\)|(?:import|export)\s[^;'"\n]*?\sfrom\s*['"]([^'"\n]+)['"]|import\s+['"]([^'"\n]+)['"]""")
PY_MODULE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w., ]+))", re.M)
URL = re.compile(r"""\b(?:https?|wss?|ftp)://([a-z0-9.-]+\.[a-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?""", re.I)
IP = re.compile(r"""['"`](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?['"`/]""")
JS_ENV = re.compile(r"""process\.env(?:\.([A-Z_][A-Z0-9_]*)|\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\])""")
PY_ENV = re.compile(r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\s*\(\s*)['"]([A-Z_][A-Z0-9_]*)['"]""")
JS_EVAL = re.compile(r"""\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*(?!['"]return this['"])[^)]|\._compile\s*\(|\bvm\.run(?:InNewContext|InThisContext|InContext)\s*\(""")
PY_EVAL = re.compile(r"""\b(?:exec|eval|compile)\s*\(|__import__\s*\(""")
DECODE = re.compile(r"""Buffer\.from\([^)]{0,200}['"](?:base64|hex)['"]|\batob\s*\(|b64decode|base64\.(?:b64|a85|b32)|bytes\.fromhex|zlib\.decompress|marshal\.loads|codecs\.decode\([^)]*rot""")
BLOB = re.compile(r"""['"`]([A-Za-z0-9+/=]{400,}|[0-9a-fA-F]{400,})['"`]""")
OBFUSCATED = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
JS_EXEC = re.compile(r"""\b(?:execSync|spawnSync|execFileSync|exec|spawn|execFile|fork)\s*\(""")
JS_NET = re.compile(r"""\bfetch\s*\(|\bXMLHttpRequest\b|\bsendBeacon\s*\(|\bnew\s+WebSocket\s*\(|\bhttps?\.(?:get|request)\s*\(""")
PY_EXEC = re.compile(r"""\b(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output|check_call)|pty\.spawn)\s*\(""")


def _module(spec: str) -> str | None:
    spec = spec.strip()
    if not spec or spec.startswith((".", "/", "#", "~", "data:", "virtual:", "\0")) or any(c in spec for c in "${}% <>*"):
        return None
    spec = spec.removeprefix("node:")
    parts = spec.split("/")
    return "/".join(parts[:2]) if spec.startswith("@") else parts[0]


def capabilities(text: str, path: str) -> set[tuple[str, str]]:
    """{(kind, value)} for one file."""
    out: set[tuple[str, str]] = set()
    is_py = path.endswith(PY_EXT)
    if is_py:
        for a, b in PY_MODULE.findall(text):
            for mod in ([a] if a else [m.strip().split(" as ")[0] for m in b.split(",")]):
                if mod:
                    out.add(("module", mod.split(".")[0]))
        for name in PY_ENV.findall(text):
            out.add(("env", name))
        if PY_EVAL.search(text):
            out.add(("eval", "exec/eval"))
        if PY_EXEC.search(text):
            out.add(("exec", "runs commands"))
    else:
        for groups in JS_MODULE.findall(text):
            mod = _module(next(g for g in groups if g))
            if mod:
                out.add(("module", mod))
        for a, b in JS_ENV.findall(text):
            out.add(("env", a or b))
        if JS_EVAL.search(text):
            out.add(("eval", "eval/new Function"))
        if JS_EXEC.search(text) and ("child_process" in text or "shelljs" in text or "execa" in text):
            out.add(("exec", "runs commands"))
        if JS_NET.search(text):
            out.add(("net", "makes web requests"))
    for host in URL.findall(text):
        out.add(("host", host.lower().rstrip(".")))
    for ip in IP.findall(text):
        if not ip.startswith(("0.", "127.", "255.")) and all(int(x) < 256 for x in ip.split(".")):
            out.add(("host", ip))
    for rx, what in SENSITIVE:
        if rx.search(text):
            out.add(("sensitive", what))
    if DECODE.search(text):
        out.add(("decode", "decodes base64/hex/compressed data"))
    if BLOB.search(text):
        out.add(("blob", "a large encoded blob"))
    if len(OBFUSCATED.findall(text)) >= 20:
        out.add(("obfuscated", "_0x… identifiers (javascript-obfuscator)"))
    if any(k == "module" and v in EXEC_MODULES for k, v in out):
        out.add(("exec", "runs commands"))
    return out


def describe(caps: set[tuple[str, str]]) -> str:
    order = ["exec", "eval", "decode", "obfuscated", "blob", "sensitive", "net", "env", "host", "module"]
    parts = []
    for kind in order:
        vals = sorted(v for k, v in caps if k == kind)
        if not vals:
            continue
        if kind in ("host", "module", "env"):
            label = {"host": "contacts", "module": "loads", "env": "reads env"}[kind]
            parts.append(f"{label} {', '.join(vals[:6])}{' …' if len(vals) > 6 else ''}")
        else:
            parts.extend(vals)
    return "; ".join(parts)


STRONG = {"exec", "eval", "decode", "obfuscated", "blob", "sensitive"}
WORD = re.compile(r"[A-Za-z_$][\w$]*|\d+(?:\.\d+)+")
# words compilers and bundlers write into code on their own
TOOLING = {"PURE", "NO_SIDE_EFFECTS", "esModule", "interopRequireDefault", "interopRequireWildcard", "exportStar",
           "jsx", "jsxs", "jsxDEV", "Fragment", "require", "exports", "module", "define", "default", "use", "strict",
           "Object", "defineProperty", "value", "true", "false", "void", "undefined", "Symbol", "toStringTag",
           "getOwnPropertyNames", "hasOwnProperty", "prototype", "call", "apply", "enumerable", "get", "set",
           "configurable", "writable", "sourceMappingURL", "commonjsHelpers", "commonjsGlobal", "createRequire",
           "import", "meta", "url", "awaiter", "generator", "assign", "extends", "classCallCheck", "createClass",
           "typeof", "toPrimitive", "toPropertyKey", "defineProperties", "WEBPACK", "webpack_require"}


def tokens(text: str) -> set[str]:
    """The words of the code (identifiers, words inside strings, version-like numbers), normalised the way
    builds rename things (_foo2 -> foo): what stays the same when code is reformatted, transpiled or its types stripped."""
    out = set()
    for w in WORD.findall(text):
        w = w.strip("_$")
        w = w.rstrip("0123456789") if not w[:1].isdigit() else w
        if len(w) > 1 and w not in TOOLING:
            out.add(w)
    return out


def risk(new: set[tuple[str, str]], built: bool) -> tuple[str, str] | None:
    """(severity, why) for capabilities that appear in a published file but nowhere in the source."""
    kinds = {k for k, _ in new}
    hosts = {v for k, v in new if k == "host" and not COMMON_HOSTS.search(v)}
    secrets = {v for k, v in new if k == "env" and SECRET_ENV.search(v)}
    exec_ = "exec" in kinds or any(v in EXEC_MODULES for k, v in new if k == "module")
    net = bool(hosts) or "net" in kinds or any(v in NET_MODULES for k, v in new if k == "module")
    if "sensitive" in kinds and (net or exec_):
        return "critical", "touches " + ", ".join(sorted(v for k, v in new if k == "sensitive")) + " and can send or run things"
    if exec_ and ("decode" in kinds or "eval" in kinds or "blob" in kinds or hosts):
        return "critical", "runs commands or decoded code"
    if secrets and net:
        return "critical", f"reads {', '.join(sorted(secrets))} and talks to the network"
    if "obfuscated" in kinds:
        return "high", "obfuscated code"
    if "sensitive" in kinds:
        return "high", "touches " + ", ".join(sorted(v for k, v in new if k == "sensitive"))
    if "eval" in kinds and ("decode" in kinds or "blob" in kinds):
        return "high", "evaluates decoded data"
    if exec_:
        return "high", "runs commands"
    if secrets:
        return "medium", f"reads {', '.join(sorted(secrets))}"
    if hosts:
        return ("low" if built else "medium"), f"names hosts that appear nowhere in the source: {', '.join(sorted(hosts)[:5])}"
    return None
