#!/usr/bin/env python3
"""
cve2detect - turn a CVE into a detection rule and a repro scaffold.

Give it a CVE id. It pulls the structured advisory (OSV + NVD), then writes:
  - a Sigma detection-rule skeleton seeded with the real metadata
  - a Nuclei template skeleton (for web/exploit-ish CVEs)
  - per-ecosystem version-check commands for the affected packages
  - a minimal repro scaffold pinned to a vulnerable version
  - a summary.md

Deterministic core works offline of any LLM. `--ai` drafts fuller rule + repro
text via the `claude` CLI (no API key needed).

    python3 cve2detect.py CVE-2021-44228
    python3 cve2detect.py CVE-2024-3094 --ai
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import urllib.request

UA = {"User-Agent": "cve2detect/0.1"}


def get_json(url):
    try:
        req = urllib.request.Request(url, headers=UA)
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except Exception:
        return None


# ---------- fetch + normalize ----------

def fetch(cve):
    osv = get_json(f"https://api.osv.dev/v1/vulns/{cve}")
    nvd = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")

    rec = {"id": cve, "summary": "", "details": "", "cvss": None, "severity": "unknown",
           "cwes": [], "affected": [], "references": []}

    # OSV CVE-level records often carry only GIT ranges with package=None; the
    # real ecosystem package + version ranges live in the GHSA/PYSEC/etc. aliases.
    records = []
    if osv:
        rec["summary"] = osv.get("summary", "")
        rec["details"] = osv.get("details", "")
        rec["references"] = [r.get("url", "") for r in osv.get("references", [])]
        records.append(osv)
        for al in osv.get("aliases", []):
            if al.startswith(("GHSA", "PYSEC", "RUSTSEC", "GO-", "GSD")):
                sub = get_json(f"https://api.osv.dev/v1/vulns/{al}")
                if sub:
                    records.append(sub)
                    if not rec["summary"]:
                        rec["summary"] = sub.get("summary", "")

    seen = set()
    for r in records:
        for a in r.get("affected", []):
            pkg = a.get("package")
            if not pkg:
                continue
            key = (pkg.get("ecosystem"), pkg.get("name"))
            if key in seen:
                continue
            introduced, fixed = None, None
            for rng in a.get("ranges", []):
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):  # ignore GIT commit ranges
                    continue
                for ev in rng.get("events", []):
                    introduced = ev.get("introduced", introduced)
                    fixed = ev.get("fixed", fixed)
            versions = a.get("versions", [])
            vuln_example = None
            if versions:
                below = [v for v in versions if v != fixed]
                vuln_example = below[-1] if below else None
            vuln_example = vuln_example or (introduced if introduced not in (None, "0") else None)
            seen.add(key)
            rec["affected"].append({
                "ecosystem": pkg.get("ecosystem", ""), "name": pkg.get("name", ""),
                "introduced": introduced, "fixed": fixed, "vuln_example": vuln_example,
            })

    if nvd and nvd.get("vulnerabilities"):
        c = nvd["vulnerabilities"][0]["cve"]
        if not rec["summary"]:
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    rec["summary"] = d["value"]
        for w in c.get("weaknesses", []):
            for d in w.get("description", []):
                if d["value"].startswith("CWE-"):
                    rec["cwes"].append(d["value"])
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                data = metrics[key][0]["cvssData"]
                rec["cvss"] = data.get("baseScore")
                rec["severity"] = data.get("baseSeverity", "").lower() or rec["severity"]
                break
        for r in c.get("references", []):
            if r.get("url") and r["url"] not in rec["references"]:
                rec["references"].append(r["url"])

    rec["cwes"] = sorted(set(rec["cwes"]))
    return rec if (osv or nvd) else None


# ---------- generators ----------

SIGMA_LEVEL = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "unknown": "medium"}

VERCHECK = {
    "PyPI": lambda p, v: f"pip show {p}            # vulnerable if version is {v or '< fixed'}",
    "npm": lambda p, v: f"npm ls {p}               # flags any tree using {p} {v or ''}",
    "crates.io": lambda p, v: f"cargo tree -i {p}  # who pulls in {p} {v or ''}",
    "Go": lambda p, v: f"govulncheck ./...         # detects {p} usage paths",
    "Maven": lambda p, v: f"mvn dependency:tree | grep {p}",
    "RubyGems": lambda p, v: f"bundle list | grep {p}",
    "Packagist": lambda p, v: f"composer show {p}",
}


def gen_sigma(rec):
    refs = "\n".join(f"        - {u}" for u in rec["references"][:5]) or "        - <add reference>"
    return textwrap.dedent(f"""\
        title: {rec['id']} - {(rec['summary'] or 'detection')[:70]}
        id: {rec['id'].lower()}-detect
        status: experimental
        description: |
            Detection skeleton for {rec['id']}. {rec['summary'][:160]}
            TODO: replace the selection below with concrete indicators
            (process, network, file, or log fields) for your data source.
        references:
{refs}
        tags:
            - {rec['id'].lower()}
""" + "".join(f"            - cwe.{c.split('-')[1]}\n" for c in rec["cwes"]) + textwrap.dedent(f"""\
        logsource:
            category: TODO      # e.g. process_creation | webserver | dns | network_connection
            product: TODO
        detection:
            selection:
                TODO_field|contains:
                    - 'TODO_indicator'   # e.g. exploit string, user-agent, path, package name
            condition: selection
        level: {SIGMA_LEVEL.get(rec['severity'], 'medium')}
        """))


def gen_nuclei(rec):
    refs = "\n".join(f"      - {u}" for u in rec["references"][:5]) or "      - <add reference>"
    sev = rec["severity"] if rec["severity"] != "unknown" else "medium"
    return textwrap.dedent(f"""\
        id: {rec['id'].lower()}

        info:
          name: {rec['id']} - {(rec['summary'] or 'check')[:60]}
          author: mstampfli
          severity: {sev}
          description: |
            {rec['summary'][:200]}
          reference:
{refs}
          classification:
            cve-id: {rec['id']}
          tags: cve,{rec['id'].lower().replace('cve-', 'cve')}

        # TODO: this is a skeleton. Fill in the request + matcher from the PoC
        # in the references above.
        http:
          - method: GET
            path:
              - "{{{{BaseURL}}}}/TODO_vulnerable_path"
            matchers-condition: and
            matchers:
              - type: word
                words:
                  - "TODO_response_marker"
              - type: status
                status:
                  - 200
        """)


REPRO = {
    "PyPI": lambda p, v: (
        "requirements.txt", f"{p}=={v or '<VULNERABLE_VERSION>'}\n",
        "repro.py", f"# repro for {{cve}} - {p} {v}\nimport {p.replace('-', '_')}  # TODO: call the vulnerable path\nprint('TODO: trigger the vulnerability')\n",
        "run.sh", "#!/usr/bin/env bash\nset -e\npython3 -m venv .venv && . .venv/bin/activate\npip install -r requirements.txt\npython3 repro.py\n"),
    "npm": lambda p, v: (
        "package.json", json.dumps({"name": "repro", "private": True, "dependencies": {p: v or "<VULNERABLE_VERSION>"}}, indent=2) + "\n",
        "index.js", f"// repro for {{cve}} - {p} {v}\nconst lib = require('{p}'); // TODO: call the vulnerable path\nconsole.log('TODO: trigger the vulnerability');\n",
        "run.sh", "#!/usr/bin/env bash\nset -e\nnpm install\nnode index.js\n"),
    "crates.io": lambda p, v: (
        "Cargo.toml", f'[package]\nname = "repro"\nversion = "0.1.0"\nedition = "2021"\n\n[dependencies]\n{p} = "={v or "<VULNERABLE_VERSION>"}"\n',
        "src/main.rs", f"// repro for {{cve}} - {p} {v}\nfn main() {{\n    // TODO: call the vulnerable path in {p}\n    println!(\"TODO: trigger the vulnerability\");\n}}\n",
        "run.sh", "#!/usr/bin/env bash\nset -e\ncargo run\n"),
}


def gen_repro(rec, outdir):
    if not rec["affected"]:
        return None
    a = rec["affected"][0]
    eco = a["ecosystem"]
    if eco not in REPRO:
        return None
    parts = REPRO[eco](a["name"], a["vuln_example"])
    reprodir = os.path.join(outdir, "repro")
    files = {}
    for i in range(0, len(parts), 2):
        files[parts[i]] = parts[i + 1].replace("{cve}", rec["id"])
    for name, content in files.items():
        path = os.path.join(reprodir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        if name.endswith(".sh"):
            os.chmod(path, 0o755)
    return reprodir


# ---------- optional AI enrichment ----------

def run_ai(rec, outdir):
    if not shutil.which("claude"):
        print("  --ai: `claude` CLI not found, skipping AI draft")
        return
    prompt = (
        "You are a detection engineer. Given this CVE, write (1) a concrete detection idea "
        "with the best data source and the specific indicators to match, and (2) a minimal "
        "proof-of-concept repro outline. Be concrete and terse. CVE data:\n\n"
        + json.dumps(rec, indent=2)
    )
    try:
        r = subprocess.run(["claude", "-p", "--output-format", "text"],
                           input=prompt, capture_output=True, text=True, timeout=180)
        if r.returncode == 0 and r.stdout.strip():
            with open(os.path.join(outdir, "ai-draft.md"), "w") as f:
                f.write(f"# AI-drafted detection + repro for {rec['id']}\n\n{r.stdout}\n")
            print("  --ai: wrote ai-draft.md")
        else:
            print(f"  --ai: claude returned no output ({r.stderr.strip()[:80]})")
    except Exception as e:
        print(f"  --ai: skipped ({e})")


# ---------- main ----------

def main():
    ap = argparse.ArgumentParser(description="turn a CVE into a detection rule + repro scaffold")
    ap.add_argument("cve", help="e.g. CVE-2021-44228")
    ap.add_argument("--out", default="cve2detect-out", help="output directory")
    ap.add_argument("--ai", action="store_true", help="also draft fuller artifacts via the claude CLI")
    args = ap.parse_args()

    cve = args.cve.upper()
    if not re.match(r"CVE-\d{4}-\d+$", cve):
        sys.exit("error: expected a CVE id like CVE-2021-44228")

    print(f"fetching {cve} from OSV + NVD ...")
    rec = fetch(cve)
    if not rec:
        sys.exit(f"error: could not find {cve} in OSV or NVD")

    outdir = os.path.join(args.out, cve)
    os.makedirs(outdir, exist_ok=True)

    with open(os.path.join(outdir, "sigma.yml"), "w") as f:
        f.write(gen_sigma(rec))
    with open(os.path.join(outdir, "nuclei.yaml"), "w") as f:
        f.write(gen_nuclei(rec))

    checks = []
    for a in rec["affected"]:
        fn = VERCHECK.get(a["ecosystem"])
        if fn:
            checks.append(f"# {a['ecosystem']}: {a['name']} (introduced {a['introduced']}, fixed {a['fixed']})\n{fn(a['name'], a['vuln_example'])}")
    if checks:
        with open(os.path.join(outdir, "version-checks.sh"), "w") as f:
            f.write("#!/usr/bin/env bash\n# version checks for " + cve + "\n\n" + "\n\n".join(checks) + "\n")

    reprodir = gen_repro(rec, outdir)

    summary = [f"# {cve}\n",
               f"**Severity:** {rec['severity']} (CVSS {rec['cvss']})  **CWE:** {', '.join(rec['cwes']) or 'n/a'}\n",
               f"\n{rec['summary']}\n",
               "\n## Affected packages\n"]
    if rec["affected"]:
        for a in rec["affected"]:
            intro = a["introduced"] if a["introduced"] not in (None, "0") else "earliest"
            summary.append(f"- `{a['ecosystem']}:{a['name']}` introduced {intro}, fixed in {a['fixed'] or 'see advisory'}")
    else:
        summary.append("- (no package-level data; likely an OS/appliance CVE - see references)")
    summary.append("\n\n## Generated\n- `sigma.yml` - detection skeleton\n- `nuclei.yaml` - web check skeleton\n"
                   "- `version-checks.sh` - per-ecosystem checks\n"
                   + (f"- `repro/` - pinned vulnerable scaffold ({rec['affected'][0]['ecosystem']})\n" if reprodir else "")
                   + "\n## References\n" + "\n".join(f"- {u}" for u in rec["references"][:10]))
    with open(os.path.join(outdir, "summary.md"), "w") as f:
        f.write("\n".join(summary) + "\n")

    if args.ai:
        run_ai(rec, outdir)

    print(f"\nwrote artifacts to {outdir}/")
    for n in sorted(os.listdir(outdir)):
        print(f"  {n}")


if __name__ == "__main__":
    main()
