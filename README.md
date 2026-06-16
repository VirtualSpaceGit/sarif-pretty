# sarif-pretty

[![Website](https://img.shields.io/badge/Website-virtualspacesec.com-2b59ff)](https://virtualspacesec.com)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org)

A tiny, dependency-free Python CLI for turning **SARIF 2.1.0** scan output into readable terminal, markdown, or JSON reports.

`sarif-pretty` is published by [Verse](https://virtualspacesec.com/pages/about-us) as a small open-source companion utility for any local SAST workflow that emits SARIF - including [**VirtualSpace AppSec**](https://virtualspacesec.com), Verse's secure code review tool for Windows that runs entirely on the user's own machine.

## Why

SARIF (Static Analysis Results Interchange Format) is a widely-used JSON schema for static-analysis findings. It is great for tooling and CI plumbing, but the raw documents are not what a developer wants to read in a terminal. `sarif-pretty` reads a `.sarif` file and renders it as:

- **a colored, severity-grouped terminal summary** (the default), suitable for a quick scan,
- **a GitHub-flavored markdown report** (`--format md`), suitable for pasting into a PR description or a CI step summary,
- **one normalized JSON record per finding** (`--format json`), suitable for piping into `jq`, `grep`, or your own scripts.

It is a single Python file that uses only the standard library - no third-party dependencies.

## Install

Requires Python 3.9 or newer. `sarif-pretty` is a single file; drop it somewhere on your `$PATH` (or invoke with `python sarif_pretty.py`).

```bash
curl -fsSL https://raw.githubusercontent.com/VirtualSpaceGit/sarif-pretty/main/sarif_pretty.py -o sarif-pretty
chmod +x sarif-pretty
```

## Usage

```bash
sarif-pretty findings.sarif                   # colored terminal output
sarif-pretty findings.sarif --no-color        # plain text
sarif-pretty findings.sarif --format md       # GitHub-flavored markdown
sarif-pretty findings.sarif --format json     # newline-delimited JSON

# CI integration: exit 1 if any warning-or-higher finding is present
sarif-pretty findings.sarif --fail-on warning

# Read from stdin
cat findings.sarif | sarif-pretty -
```

### CLI options

| Flag | Default | Description |
|---|---|---|
| `path` | (required) | Path to a SARIF 2.1.0 JSON file. Use `-` to read from stdin. |
| `--format {ansi,md,json}` | `ansi` | Output format. |
| `--no-color` | off | Suppress ANSI colors in `ansi` format. |
| `--fail-on {none,note,warning,error}` | `none` | Exit with code 1 if any finding meets or exceeds the given level. Useful in CI. |

## Example

`sample.sarif` in this repository contains three findings - two `error`-level and one `warning`-level - emitted by VirtualSpace AppSec against a small Python project:

```bash
$ sarif-pretty sample.sarif --format md
# Scan findings

**Total:** 3

## HIGH (2)

| Rule | CWE | Location | Message |
|---|---|---|---|
| `VS-PY-502-PICKLE` (InsecureDeserialization) | CWE-502 | `src/loader.py:42` | pickle.load on attacker-controllable input |
| `VS-PY-89-SQLI` (SqlInjection) | CWE-89 | `src/users.py:18` | User input concatenated into SQL query |

## MEDIUM (1)

| Rule | CWE | Location | Message |
|---|---|---|---|
| `VS-PY-327-MD5` (WeakHash) | CWE-327, CWE-916 | `src/auth.py:7` | MD5 used for password storage |
```

## SARIF fields recognised

`sarif-pretty` reads the fields most commonly emitted by SAST tools:

- `runs[].tool.driver.name`
- `runs[].tool.driver.rules[]` - used to look up the rule name when a finding only carries an id
- `runs[].results[].ruleId`, `level`, `message.text`
- `runs[].results[].locations[0].physicalLocation.artifactLocation.uri`
- `runs[].results[].locations[0].physicalLocation.region.startLine` (and `startColumn`, `snippet.text`)
- `runs[].results[].properties.cwe` - a non-standard convention many tools use to attach CWE identifiers

Findings that lack any of these fields gracefully degrade rather than fail.

## License

MIT - see [LICENSE](LICENSE).
