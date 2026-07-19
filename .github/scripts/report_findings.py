#!/usr/bin/env python3
"""Post a CWE-classified security findings summary to the PR and file
issues for Critical findings. Reads GitHub code scanning alerts (already
uploaded by the static-analysis job) plus the Nuclei DAST artifact, if
present. Read-only with respect to source: this only writes a PR comment
and issues, never repository files.
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

REPO = os.environ["GITHUB_REPOSITORY"]
PR_NUMBER = os.environ["PR_NUMBER"]
PR_REF = f"refs/pull/{PR_NUMBER}/merge"
RUN_ID = os.environ["GITHUB_RUN_ID"]
SHA = os.environ["PR_SHA"][:7]
SERVER_URL = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

COMMENT_MARKER = "<!-- webgoat-security-scan-report -->"

SEV_ORDER = ["critical", "high", "medium", "low"]
SEV_EMOJI = {"critical": "\U0001F534", "high": "\U0001F7E0", "medium": "\U0001F7E1", "low": "\U000026AA"}

CWE_TITLES = {
    "CWE-78": "OS Command Injection", "CWE-89": "SQL Injection", "CWE-352": "Cross-Site Request Forgery",
    "CWE-22": "Path Traversal", "CWE-23": "Relative Path Traversal", "CWE-918": "Server-Side Request Forgery",
    "CWE-502": "Deserialization of Untrusted Data", "CWE-330": "Insufficiently Random Values",
    "CWE-1004": "Cookie Missing HttpOnly Flag", "CWE-614": "Cookie Missing Secure Attribute",
    "CWE-601": "Open Redirect", "CWE-200": "Sensitive Information Exposure",
    "CWE-319": "Cleartext Transmission of Sensitive Data",
    "CWE-345": "Insufficient Data Authenticity Verification", "CWE-829": "Untrusted Functionality Inclusion",
    "CWE-501": "Trust Boundary Violation", "CWE-1357": "Untrustworthy Component Reliance",
    "CWE-353": "Missing Integrity Check", "CWE-328": "Use of Weak Hash",
    "CWE-400": "Uncontrolled Resource Consumption", "CWE-434": "Unrestricted Dangerous File Upload",
    "CWE-73": "External Control of File Name/Path", "CWE-94": "Code Injection", "CWE-835": "Infinite Loop",
    "CWE-306": "Missing Authentication for Critical Function", "CWE-121": "Stack-based Buffer Overflow",
    "CWE-787": "Out-of-bounds Write", "CWE-120": "Buffer Copy Without Size Check",
    "CWE-674": "Uncontrolled Recursion", "CWE-915": "Improper Object Attribute Modification",
    "CWE-20": "Improper Input Validation", "CWE-489": "Active Debug Code",
}


def gh_api_get(path_with_query, paginate=True):
    """GET only -- never pass -f/-F here, gh api silently switches those to POST."""
    args = ["--method", "GET"]
    if paginate:
        args.append("--paginate")
    args.append(path_with_query)
    out = subprocess.run(["gh", "api"] + args, capture_output=True, text=True)
    if out.returncode != 0:
        print(f"gh api GET {path_with_query} failed: {out.stderr}", file=sys.stderr)
        return None
    return out.stdout


def fetch_alerts():
    import urllib.parse
    ref_q = urllib.parse.quote(PR_REF, safe="")
    raw = gh_api_get(f"repos/{REPO}/code-scanning/alerts?ref={ref_q}&state=open&per_page=100")
    if not raw:
        return []
    alerts = []
    decoder = json.JSONDecoder()
    idx = 0
    raw = raw.strip()
    while idx < len(raw):
        obj, end = decoder.raw_decode(raw, idx)
        alerts.extend(obj)
        idx = end
        while idx < len(raw) and raw[idx] in " \n\t":
            idx += 1
    return alerts


def norm_sev(raw):
    if raw == "CRITICAL" or raw == "critical":
        return "critical"
    if raw in ("HIGH", "error", "high"):
        return "high"
    if raw in ("MEDIUM", "warning", "medium"):
        return "medium"
    return "low"


def load_cve_cache():
    path = os.path.join(SCRIPT_DIR, "cve_cwe_cache.json")
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    return {}


def nvd_lookup(cve, timeout=5):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            d = json.load(r)
        vulns = d.get("vulnerabilities", [])
        if not vulns:
            return None
        v = vulns[0]["cve"]
        cwes = sorted({desc["value"] for w in v.get("weaknesses", []) for desc in w["description"] if desc["value"].startswith("CWE-")})
        sev = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in v.get("metrics", {}):
                sev = v["metrics"][key][0]["cvssData"].get("baseSeverity")
                break
        return {"cwes": cwes, "severity": sev}
    except Exception:
        return None


def build_findings(alerts, cve_cache):
    by_cwe = {}
    fp_secrets = []
    live_lookups = 0
    max_live_lookups = 8  # keep CI runtime bounded; unknown CVEs beyond this fall back uncategorized

    for a in alerts:
        tool = a["tool"]["name"]
        rule = a["rule"]
        loc = a["most_recent_instance"]["location"]

        if tool == "Semgrep OSS":
            cwes = [t.split(":")[0] for t in (rule.get("tags") or []) if t.startswith("CWE-")]
            sev = norm_sev(rule.get("severity"))
            if not cwes:
                cwes = ["CWE-Unclassified"]
            for c in cwes:
                by_cwe.setdefault(c, {"title": CWE_TITLES.get(c, c), "items": []})
                by_cwe[c]["items"].append({
                    "source": "Semgrep", "id": rule["id"].split(".")[-1], "sev": sev,
                    "loc": f"{loc.get('path')}:{loc.get('start_line')}", "url": a["html_url"],
                })
        elif tool == "Trivy":
            rid = rule["id"]
            if rid.startswith("CVE-"):
                info = cve_cache.get(rid)
                if info is None and live_lookups < max_live_lookups:
                    info = nvd_lookup(rid)
                    live_lookups += 1
                    time.sleep(1)
                if info is None:
                    info = {"cwes": [], "severity": rule.get("security_severity_level")}
                cwes = info.get("cwes") or ["CWE-1357"]
                sev = norm_sev(info.get("severity") or rule.get("security_severity_level"))
                msg = a["most_recent_instance"]["message"]["text"]
                pkg = next((l.split(": ", 1)[1] for l in msg.splitlines() if l.startswith("Package:")), "?")
                inst = next((l.split(": ", 1)[1] for l in msg.splitlines() if l.startswith("Installed Version:")), "?")
                fix = next((l.split(": ", 1)[1] for l in msg.splitlines() if l.startswith("Fixed Version:")), "none")
                for c in cwes:
                    by_cwe.setdefault(c, {"title": CWE_TITLES.get(c, c), "items": []})
                    by_cwe[c]["items"].append({
                        "source": "Trivy", "id": rid, "sev": sev,
                        "loc": f"{loc.get('path')}:{loc.get('start_line')}",
                        "detail": f"`{pkg}@{inst}` → fix `{fix}`", "url": a["html_url"],
                    })
            elif rid == "jwt-token":
                fp_secrets.append({"path": loc.get("path"), "line": loc.get("start_line")})

    return by_cwe, fp_secrets


def load_nuclei_findings():
    try:
        subprocess.run(
            ["gh", "run", "download", RUN_ID, "-n", "nuclei-results", "-D", "nuclei-dl"],
            check=True, capture_output=True, text=True,
        )
    except subprocess.CalledProcessError:
        return []
    path = "nuclei-dl/nuclei-results.json"
    if not os.path.exists(path):
        return []
    findings = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = d.get("info", {})
            if info.get("severity") == "info":
                continue
            if d.get("port") != "8080":
                continue
            findings.append({
                "name": info.get("name"), "severity": info.get("severity"),
                "matched": d.get("matched-at"),
            })
    return findings


def sev_counts(by_cwe):
    counts = {s: 0 for s in SEV_ORDER}
    seen = set()
    for cwe, data in by_cwe.items():
        for it in data["items"]:
            key = (it["source"], it["id"], it["loc"])
            if key in seen:
                continue
            seen.add(key)
            counts[it["sev"]] += 1
    return counts, len(seen)


def build_comment_body(by_cwe, fp_secrets, nuclei_findings, critical_issue_links):
    counts, total = sev_counts(by_cwe)
    groups = sorted(by_cwe.items(), key=lambda kv: -len(kv[1]["items"]))

    lines = [COMMENT_MARKER]
    lines.append("## \U0001F6E1️ Security Scan Report")
    lines.append("")
    lines.append(
        f"Run [#{RUN_ID}]({SERVER_URL}/{REPO}/actions/runs/{RUN_ID}) on commit `{SHA}` "
        f"· **{total} static findings** (Semgrep + Trivy){' · **' + str(len(nuclei_findings)) + ' live DAST findings** (Nuclei)' if nuclei_findings else ''}"
    )
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for s in SEV_ORDER:
        if counts[s]:
            lines.append(f"| {SEV_EMOJI[s]} {s.capitalize()} | {counts[s]} |")
    lines.append("")
    lines.append(
        "> WebGoat is an intentionally vulnerable training app — most findings below are the lessons "
        "working as designed, not accidental defects. Real infrastructure/dependency risk is called out "
        "explicitly per group."
    )
    lines.append("")

    for sev in SEV_ORDER:
        sev_groups = [(c, d) for c, d in groups if any(it["sev"] == sev for it in d["items"])]
        if not sev_groups:
            continue
        lines.append(f"### {SEV_EMOJI[sev]} {sev.capitalize()}")
        lines.append("")
        for cwe, data in sev_groups:
            items = [it for it in data["items"] if it["sev"] == sev]
            if not items:
                continue
            issue_link = critical_issue_links.get(cwe, "") if sev == "critical" else ""
            summary = f"**{cwe}: {data['title']}** — {len(items)} finding(s){' · tracked in ' + issue_link if issue_link else ''}"
            lines.append("<details>")
            lines.append(f"<summary>{summary}</summary>")
            lines.append("")
            lines.append("| Source | Location | Detail |")
            lines.append("|---|---|---|")
            for it in items[:15]:
                detail = it.get("detail", it["id"])
                loc_cell = f"[`{it['loc']}`]({it['url']})" if it.get("url") else f"`{it['loc']}`"
                lines.append(f"| {it['source']} | {loc_cell} | {detail} |")
            if len(items) > 15:
                lines.append(f"| … | | *{len(items) - 15} more — see [Security › Code scanning]({SERVER_URL}/{REPO}/security/code-scanning) filtered to `{cwe}`* |")
            lines.append("")
            lines.append("</details>")
            lines.append("")

    if nuclei_findings:
        lines.append("### \U0001F30E Dynamic scan (Nuclei, live app)")
        lines.append("")
        lines.append("Notable findings against the booted WebGoat instance (informational/low-severity noise filtered out):")
        lines.append("")
        for f in nuclei_findings:
            lines.append(f"- **{f['severity'].capitalize()}** — {f['name']} — `{f['matched']}`")
        lines.append("")

    if fp_secrets:
        lines.append(f"### ⚠️ Likely false positives — secret scanner ({len(fp_secrets)})")
        lines.append("")
        lines.append("Trivy's `jwt-token` rule fired on WebGoat's own JWT lesson fixtures (docs/HTML/sample logs), not real credentials:")
        lines.append("")
        for s in fp_secrets:
            lines.append(f"- `{s['path']}:{s['line']}`")
        lines.append("")

    lines.append("---")
    lines.append(
        "*Severity is normalized across tools: Trivy uses NVD CVSS `baseSeverity`; Semgrep has no CVSS score "
        "so its SARIF level stands in (`error`→High, `warning`→Medium). This report is informational only "
        "— nothing here blocks merge or was auto-remediated.*"
    )
    return "\n".join(lines)


def upsert_pr_comment(body):
    raw = gh_api_get(f"repos/{REPO}/issues/{PR_NUMBER}/comments?per_page=100")
    existing_id = None
    if raw:
        decoder = json.JSONDecoder()
        idx = 0
        raw = raw.strip()
        while idx < len(raw):
            obj, end = decoder.raw_decode(raw, idx)
            for c in obj:
                if COMMENT_MARKER in c.get("body", ""):
                    existing_id = c["id"]
            idx = end
            while idx < len(raw) and raw[idx] in " \n\t":
                idx += 1

    with open("comment_body.json", "w") as f:
        json.dump({"body": body}, f)

    if existing_id:
        subprocess.run(["gh", "api", f"repos/{REPO}/issues/comments/{existing_id}",
                         "--method", "PATCH", "--input", "comment_body.json"], check=False)
        print(f"Updated existing PR comment {existing_id}")
    else:
        subprocess.run(["gh", "api", f"repos/{REPO}/issues/{PR_NUMBER}/comments",
                         "--method", "POST", "--input", "comment_body.json"], check=False)
        print("Created new PR comment")


def find_existing_issue(marker):
    raw = gh_api_get(f"repos/{REPO}/issues?state=all&labels=security,critical&per_page=100")
    if not raw:
        return None
    decoder = json.JSONDecoder()
    idx = 0
    raw = raw.strip()
    while idx < len(raw):
        obj, end = decoder.raw_decode(raw, idx)
        for issue in obj:
            if marker in issue.get("body", ""):
                return issue["html_url"]
        idx = end
        while idx < len(raw) and raw[idx] in " \n\t":
            idx += 1
    return None


def create_critical_issues(by_cwe):
    links = {}
    for cwe, data in by_cwe.items():
        crit_items = [it for it in data["items"] if it["sev"] == "critical"]
        if not crit_items:
            continue
        marker = f"<!-- finding: {cwe} -->"
        existing = find_existing_issue(marker)
        if existing:
            print(f"Issue already exists for {cwe}: {existing}")
            links[cwe] = existing
            continue

        title = f"[Security] {cwe}: {data['title']} — {len(crit_items)} critical finding(s)"
        body_lines = [
            marker,
            f"## {cwe}: {data['title']}",
            "",
            f"Detected by the [security-scan workflow]({SERVER_URL}/{REPO}/actions/runs/{RUN_ID}) on "
            f"PR [#{PR_NUMBER}]({SERVER_URL}/{REPO}/pull/{PR_NUMBER}), commit `{SHA}`.",
            "",
            "| Source | Location | Detail |",
            "|---|---|---|",
        ]
        for it in crit_items:
            detail = it.get("detail", it["id"])
            loc_cell = f"[`{it['loc']}`]({it['url']})" if it.get("url") else f"`{it['loc']}`"
            body_lines.append(f"| {it['source']} | {loc_cell} | {detail} |")
        body_lines += [
            "",
            "This is a Critical-severity finding — filed automatically because it clears the pipeline's "
            "Critical threshold, not because a human triaged it yet. Please review and either fix, "
            "suppress with justification, or close as a false positive.",
            "",
            "_Filed automatically by the security-scan workflow. This issue is informational; no code was changed._",
        ]
        body = "\n".join(body_lines)
        with open("issue_body.json", "w") as f:
            json.dump({"title": title, "body": body, "labels": ["security", "critical"]}, f)
        out = subprocess.run(["gh", "api", f"repos/{REPO}/issues", "--method", "POST",
                               "--input", "issue_body.json"], capture_output=True, text=True)
        if out.returncode == 0:
            issue = json.loads(out.stdout)
            print(f"Created issue for {cwe}: {issue['html_url']}")
            links[cwe] = issue["html_url"]
        else:
            print(f"Failed to create issue for {cwe}: {out.stderr}", file=sys.stderr)
    return links


def main():
    alerts = fetch_alerts()
    print(f"Fetched {len(alerts)} open alerts for {PR_REF}")
    cve_cache = load_cve_cache()
    by_cwe, fp_secrets = build_findings(alerts, cve_cache)
    nuclei_findings = load_nuclei_findings()

    critical_issue_links = create_critical_issues(by_cwe)
    comment = build_comment_body(by_cwe, fp_secrets, nuclei_findings, critical_issue_links)
    upsert_pr_comment(comment)


if __name__ == "__main__":
    main()
