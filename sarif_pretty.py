#!/usr/bin/env python3
"""
sarif-pretty - render SARIF 2.1.0 reports as readable terminal, markdown,
or JSON output.

A tiny dependency-free CLI for SARIF results from any tool that emits the
format. Useful as a companion to local SAST runs in CI, including
VirtualSpace AppSec (https://virtualspacesec.com).

Usage:
    sarif-pretty findings.sarif                       # ANSI table to stdout
    sarif-pretty findings.sarif --format md           # GitHub-flavored markdown
    sarif-pretty findings.sarif --format json         # one normalized JSON object per line
    sarif-pretty findings.sarif --fail-on warning     # exit 1 if any warning+
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Iterator, List, Sequence

# --- Level normalization ----------------------------------------------------

LEVEL_RANK = {"none": 0, "note": 1, "warning": 2, "error": 3}
LEVEL_LABEL = {"none": "INFO", "note": "LOW", "warning": "MEDIUM", "error": "HIGH"}
ANSI = {
    "none":    "\033[37m",
    "note":    "\033[34m",
    "warning": "\033[33m",
    "error":   "\033[31m",
    "reset":   "\033[0m",
    "bold":    "\033[1m",
    "dim":     "\033[2m",
}


@dataclass
class Finding:
    rule_id: str
    rule_name: str = ""
    level: str = "warning"
    message: str = ""
    file: str = ""
    line: int = 0
    column: int = 0
    snippet: str = ""
    cwe: List[str] = field(default_factory=list)
    tool: str = ""

    @property
    def rank(self) -> int:
        return LEVEL_RANK.get(self.level, 1)


# --- Parsing ----------------------------------------------------------------

def parse_sarif(doc: dict) -> Iterator[Finding]:
    """Yield Finding objects from a SARIF 2.1.0 document."""
    for run in doc.get("runs", []) or []:
        driver = (run.get("tool") or {}).get("driver") or {}
        tool = driver.get("name", "")
        rules = {r.get("id"): r for r in (driver.get("rules") or [])}
        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "")
            rule = rules.get(rule_id, {}) or {}
            level = (
                res.get("level")
                or (rule.get("defaultConfiguration") or {}).get("level")
                or "warning"
            )
            msg = (res.get("message") or {}).get("text", "")
            loc_list = res.get("locations") or []
            phys = (loc_list[0].get("physicalLocation") if loc_list else {}) or {}
            art = phys.get("artifactLocation") or {}
            reg = phys.get("region") or {}
            snip = (reg.get("snippet") or {}).get("text", "")
            cwe = list((res.get("properties") or {}).get("cwe", []) or [])
            yield Finding(
                rule_id=rule_id,
                rule_name=(rule.get("name") or ""),
                level=level,
                message=msg,
                file=art.get("uri", ""),
                line=int(reg.get("startLine", 0) or 0),
                column=int(reg.get("startColumn", 0) or 0),
                snippet=snip,
                cwe=cwe,
                tool=tool,
            )


# --- Renderers --------------------------------------------------------------

def _bucket(findings: Sequence[Finding]) -> dict:
    out: dict = {}
    for f in findings:
        out.setdefault(f.level, []).append(f)
    return out


def render_ansi(findings: Sequence[Finding], use_color: bool) -> str:
    out: List[str] = []
    by_level = _bucket(findings)
    out.append(f"{len(findings)} finding(s)")
    for level in ("error", "warning", "note", "none"):
        bucket = by_level.get(level, [])
        if not bucket:
            continue
        label = LEVEL_LABEL[level]
        color = ANSI[level] if use_color else ""
        reset = ANSI["reset"] if use_color else ""
        bold = ANSI["bold"] if use_color else ""
        out.append("")
        out.append(f"{bold}{color}{label}{reset} ({len(bucket)})")
        out.append("-" * 60)
        for f in bucket:
            head = f"  {f.rule_id}"
            if f.rule_name:
                head += f" {f.rule_name}"
            if f.cwe:
                head += f"  [{' '.join(f.cwe)}]"
            out.append(head)
            loc = f.file or "<no-location>"
            if f.line:
                loc = f"{loc}:{f.line}"
                if f.column:
                    loc = f"{loc}:{f.column}"
            out.append(f"    {loc}")
            if f.message:
                out.append(f"    {f.message}")
            if f.snippet:
                out.append(f"    > {f.snippet.strip()}")
            out.append("")
    return "\n".join(out)


def render_markdown(findings: Sequence[Finding]) -> str:
    out: List[str] = ["# Scan findings", "", f"**Total:** {len(findings)}", ""]
    by_level = _bucket(findings)
    for level in ("error", "warning", "note", "none"):
        bucket = by_level.get(level, [])
        if not bucket:
            continue
        out.append(f"## {LEVEL_LABEL[level]} ({len(bucket)})")
        out.append("")
        out.append("| Rule | CWE | Location | Message |")
        out.append("|---|---|---|---|")
        for f in bucket:
            cwe = ", ".join(f.cwe) if f.cwe else "-"
            loc = f.file or ""
            if f.line:
                loc = f"`{loc}:{f.line}`"
            elif loc:
                loc = f"`{loc}`"
            else:
                loc = "-"
            rule = f"`{f.rule_id}`"
            if f.rule_name:
                rule = f"`{f.rule_id}` ({f.rule_name})"
            msg = (f.message or "-").replace("|", "\\|")
            out.append(f"| {rule} | {cwe} | {loc} | {msg} |")
        out.append("")
    return "\n".join(out)


def render_json(findings: Sequence[Finding]) -> str:
    return "\n".join(
        json.dumps(
            {
                "rule_id": f.rule_id,
                "rule_name": f.rule_name,
                "level": f.level,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "snippet": f.snippet,
                "cwe": f.cwe,
                "tool": f.tool,
            }
        )
        for f in findings
    )


# --- CLI --------------------------------------------------------------------

def main(argv: Sequence[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="sarif-pretty",
        description="Render SARIF 2.1.0 reports as readable terminal, markdown, or JSON output.",
    )
    p.add_argument("path", help="Path to a SARIF 2.1.0 JSON file ('-' for stdin)")
    p.add_argument(
        "--format",
        choices=("ansi", "md", "json"),
        default="ansi",
        help="Output format (default: ansi)",
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Suppress ANSI colors in 'ansi' format",
    )
    p.add_argument(
        "--fail-on",
        choices=("none", "note", "warning", "error"),
        default="none",
        help="Exit 1 if any finding meets or exceeds this level (default: none)",
    )
    args = p.parse_args(argv)

    if args.path == "-":
        raw = sys.stdin.read()
    else:
        with open(args.path, "r", encoding="utf-8") as f:
            raw = f.read()

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"error: input is not valid JSON: {e}", file=sys.stderr)
        return 2

    findings = list(parse_sarif(doc))

    use_color = (
        (not args.no_color)
        and not os.environ.get("NO_COLOR")
        and sys.stdout.isatty()
        and (os.name != "nt" or os.environ.get("TERM") not in (None, ""))
    )
    if args.format == "ansi":
        print(render_ansi(findings, use_color))
    elif args.format == "md":
        print(render_markdown(findings))
    else:
        print(render_json(findings))

    threshold = LEVEL_RANK[args.fail_on]
    if threshold > 0 and any(f.rank >= threshold for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
