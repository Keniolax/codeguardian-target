#!/usr/bin/env python3
"""Security gate: turn scanner reports into one list of findings and decide pass or fail.

The CI workflow runs this file from the BASE commit, never from the pull request, so a
pull request cannot change the rules that judge it. Standard library only.

Commands:
  normalize-semgrep REPORT OUT
  normalize-gitleaks REPORT OUT
  normalize-trivy HEAD_REPORT BASE_REPORT OUT    (keeps findings new in head)
  normalize-zap REPORT OUT
  decide --scans DIR --diff PATCH --suppressions FILE --out FILE [--report-only]
  check-suppressions FILE
"""

import argparse
import fnmatch
import hashlib
import json
import re
import sys
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# A new finding at or above this severity fails the gate. Lower ones are reported only.
BLOCK_AT = {
    "semgrep": "medium",  # Semgrep ERROR and WARNING block; INFO is advice
    "gitleaks": "info",  # every new secret blocks
    "trivy": "medium",  # new CRITICAL, HIGH or MEDIUM CVE or misconfiguration blocks
    "zap": "medium",  # ZAP risk Medium or High blocks; Low and Informational do not
}

# Inline comments that would let a pull request silence a scanner in its own code.
INLINE_SUPPRESSION = re.compile(r"nosemgrep|gitleaks:allow|trivy:ignore|nosec\b")

MIN_REASON = 20


def fingerprint(*parts):
    return hashlib.sha256("|".join(str(p) for p in parts).encode()).hexdigest()[:16]


def finding(scanner, rule_id, severity, file, line, title, message, url=""):
    return {
        "id": fingerprint(scanner, rule_id, file, line, message[:200]),
        "scanner": scanner,
        "rule_id": str(rule_id),
        "severity": severity,
        "file": file,
        "line": int(line or 0),
        "title": title[:200],
        "message": message[:1000],
        "url": url,
    }


def load_json(path):
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text) if text.strip() else None


def write_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# --- Semgrep ---------------------------------------------------------------------------

SEMGREP_SEVERITY = {"ERROR": "high", "WARNING": "medium", "INFO": "info",
                    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def normalize_semgrep(report):
    out = []
    for r in report.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        refs = meta.get("references") or []
        out.append(finding(
            "semgrep", r["check_id"], SEMGREP_SEVERITY.get(extra.get("severity", ""), "medium"),
            r.get("path", ""), r.get("start", {}).get("line", 0),
            r["check_id"].rsplit(".", 1)[-1], extra.get("message", ""),
            refs[0] if refs else meta.get("source", ""),
        ))
    return out


# --- Gitleaks --------------------------------------------------------------------------

def normalize_gitleaks(report):
    out = []
    for r in report or []:
        out.append(finding(
            "gitleaks", r.get("RuleID", ""), "high", r.get("File", ""), r.get("StartLine", 0),
            r.get("Description", "secret"),
            f"{r.get('Description', 'Secret')} committed in {str(r.get('Commit', ''))[:12]}",
        ))
    return out


# --- Trivy -----------------------------------------------------------------------------

def trivy_items(report):
    """Yield (key, finding) for every vulnerability and failed misconfiguration."""
    for res in (report or {}).get("Results", []) or []:
        target = res.get("Target", "")
        for v in res.get("Vulnerabilities", []) or []:
            key = ("vuln", target, v["VulnerabilityID"], v.get("PkgName"), v.get("InstalledVersion"))
            locs = v.get("Locations") or [{}]
            fixed = v.get("FixedVersion") or "none"
            msg = (f"{v.get('PkgName')} {v.get('InstalledVersion')} has {v['VulnerabilityID']}"
                   f" (fixed in {fixed}). {v.get('Title', '')}")
            yield key, finding("trivy", v["VulnerabilityID"], v.get("Severity", "UNKNOWN").lower(),
                               target, locs[0].get("StartLine", 0), v.get("Title") or v["VulnerabilityID"],
                               msg, v.get("PrimaryURL", ""))
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status") != "FAIL":
                continue
            line = (m.get("CauseMetadata") or {}).get("StartLine", 0)
            # No line in the key: a change that shifts lines must not turn old findings new.
            key = ("misconfig", target, m.get("ID"))
            yield key, finding("trivy", m.get("ID", ""), m.get("Severity", "UNKNOWN").lower(), target,
                               line, m.get("Title", ""), m.get("Message", ""), m.get("PrimaryURL", ""))


def normalize_trivy(head, base):
    """Keep only what head adds. Both scans ran in one job with one database.

    Keys are counted, not just compared: if the base has a check failing twice in a file
    and the head has it three times, one finding is new.
    """
    remaining = {}
    for k, _ in trivy_items(base):
        remaining[k] = remaining.get(k, 0) + 1
    seen, out = set(), []
    for k, f in trivy_items(head):
        if k[0] == "vuln" and k in seen:
            continue  # one package version can be listed under several targets
        seen.add(k)
        if remaining.get(k, 0) > 0:
            remaining[k] -= 1
            continue
        out.append(f)
    return out


# --- ZAP -------------------------------------------------------------------------------

ZAP_RISK = {"3": "high", "2": "medium", "1": "low", "0": "info"}


def normalize_zap(report):
    out = []
    for site in (report or {}).get("site", []) or []:
        for a in site.get("alerts", []) or []:
            inst = (a.get("instances") or [{}])[0]
            uri = inst.get("uri", site.get("@name", ""))
            refs = re.findall(r"https?://[^\s<]+", a.get("reference", ""))
            out.append(finding(
                "zap", a.get("pluginid", ""), ZAP_RISK.get(str(a.get("riskcode")), "info"),
                uri, 0, a.get("alert") or a.get("name", ""),
                f"{a.get('alert') or a.get('name', '')} on {a.get('count', len(a.get('instances') or []))} URL(s),"
                f" for example {uri}", refs[0] if refs else "",
            ))
    return out


# --- Inline suppressions in the diff ----------------------------------------------------

def inline_suppressions(patch_text):
    out, current, line_no = [], "", 0
    for raw in patch_text.splitlines():
        if raw.startswith("+++ "):
            current = raw[6:] if raw.startswith("+++ b/") else raw[4:]
            continue
        hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", raw)
        if hunk:
            line_no = int(hunk.group(1)) - 1
            continue
        if raw.startswith("+") and not raw.startswith("+++"):
            line_no += 1
            m = INLINE_SUPPRESSION.search(raw)
            if m and not current.startswith(".gate/"):
                out.append(finding(
                    "gate", "inline-suppression", "high", current, line_no,
                    "Inline scanner suppression",
                    f"The change adds '{m.group(0)}'. Suppressions belong in .gate/suppressions.json"
                    " with a reason, where review can see them.",
                ))
        elif not raw.startswith("-"):
            line_no += 1
    return out


# --- Suppressions ----------------------------------------------------------------------

def load_suppressions(path):
    data = load_json(path) or {}
    entries = data.get("suppressions", [])
    problems = []
    for i, s in enumerate(entries):
        if not s.get("scanner") or not s.get("rule_id"):
            problems.append(f"entry {i}: scanner and rule_id are required")
        if len((s.get("reason") or "").strip()) < MIN_REASON:
            problems.append(f"entry {i} ({s.get('scanner')}/{s.get('rule_id')}): reason must be at"
                            f" least {MIN_REASON} characters")
    return entries, problems


def suppressed_by(f, entries):
    for s in entries:
        if s["scanner"] != f["scanner"] or str(s["rule_id"]) != f["rule_id"]:
            continue
        if fnmatch.fnmatch(f["file"], s.get("path", "*")):
            return s
    return None


def blocks(f):
    limit = BLOCK_AT.get(f["scanner"], "info")
    sev = f["severity"] if f["severity"] in SEVERITIES else "medium"
    return SEVERITIES.index(sev) <= SEVERITIES.index(limit)


# --- Decide ----------------------------------------------------------------------------

def decide(scans_dir, patch_path, suppressions_path, report_only):
    entries, problems = load_suppressions(suppressions_path)
    findings, missing = [], []
    for scanner in ("semgrep", "gitleaks", "trivy", "zap"):
        p = Path(scans_dir) / f"{scanner}.json"
        if not p.exists():
            missing.append(scanner)
            continue
        findings.extend(load_json(p) or [])
    if patch_path and Path(patch_path).exists():
        findings.extend(inline_suppressions(Path(patch_path).read_text(encoding="utf-8", errors="replace")))

    blocking, reported, silenced = [], [], []
    for f in findings:
        s = suppressed_by(f, entries)
        if s:
            silenced.append({**f, "suppressed_reason": s["reason"]})
        elif blocks(f):
            blocking.append(f)
        else:
            reported.append(f)

    ok = not blocking and not missing and not problems
    return {
        "result": "report-only" if report_only else ("pass" if ok else "fail"),
        "missing_scanners": missing,
        "suppression_problems": problems,
        "blocking": blocking,
        "reported": reported,
        "suppressed": silenced,
    }


def summary_markdown(d):
    lines = [f"## Security gate: {d['result'].upper()}", ""]
    if d["missing_scanners"]:
        lines.append(f"Scanner output missing (a gate that cannot run must not pass): {', '.join(d['missing_scanners'])}")
    for p in d["suppression_problems"]:
        lines.append(f"- Suppression problem: {p}")
    counts = {}
    for f in d["blocking"]:
        counts[f["scanner"]] = counts.get(f["scanner"], 0) + 1
    lines += ["| Scanner | Blocking | Reported | Suppressed |", "|---|---|---|---|"]
    for sc in ("semgrep", "gitleaks", "trivy", "zap", "gate"):
        b = sum(1 for f in d["blocking"] if f["scanner"] == sc)
        r = sum(1 for f in d["reported"] if f["scanner"] == sc)
        s = sum(1 for f in d["suppressed"] if f["scanner"] == sc)
        lines.append(f"| {sc} | {b} | {r} | {s} |")
    if d["blocking"]:
        lines += ["", "### Blocking findings", ""]
        for f in d["blocking"][:50]:
            lines.append(f"- `{f['scanner']}` `{f['rule_id']}` ({f['severity']}) {f['file']}:{f['line']} — {f['title']}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("semgrep", "gitleaks", "zap"):
        p = sub.add_parser(f"normalize-{name}")
        p.add_argument("report")
        p.add_argument("out")
    p = sub.add_parser("normalize-trivy")
    p.add_argument("head")
    p.add_argument("base")
    p.add_argument("out")
    p = sub.add_parser("decide")
    p.add_argument("--scans", required=True)
    p.add_argument("--diff")
    p.add_argument("--suppressions", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--summary")
    p.add_argument("--report-only", action="store_true")
    p = sub.add_parser("check-suppressions")
    p.add_argument("file")
    a = ap.parse_args(argv)

    if a.cmd == "normalize-semgrep":
        write_json(a.out, normalize_semgrep(load_json(a.report) or {}))
    elif a.cmd == "normalize-gitleaks":
        write_json(a.out, normalize_gitleaks(load_json(a.report)))
    elif a.cmd == "normalize-zap":
        write_json(a.out, normalize_zap(load_json(a.report)))
    elif a.cmd == "normalize-trivy":
        write_json(a.out, normalize_trivy(load_json(a.head), load_json(a.base)))
    elif a.cmd == "check-suppressions":
        _, problems = load_suppressions(a.file)
        for p in problems:
            print(p, file=sys.stderr)
        return 1 if problems else 0
    elif a.cmd == "decide":
        d = decide(a.scans, a.diff, a.suppressions, a.report_only)
        write_json(a.out, d)
        md = summary_markdown(d)
        if a.summary:
            with open(a.summary, "a", encoding="utf-8") as fh:
                fh.write(md)
        print(md)
        return 1 if d["result"] == "fail" else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
