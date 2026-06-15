#!/usr/bin/env python3
"""
cve2detect - triage a CVE and bootstrap detection + reproduction.

Give it a CVE id. It pulls the advisory from OSV + NVD and enriches it with the
data a defender actually triages on:

  - KEV       : is it on CISA's Known Exploited Vulnerabilities list (in-the-wild)?
  - EPSS      : FIRST's probability that it will be exploited in the next 30 days
  - exploit?  : is there a public exploit (NVD reference tags + known exploit hosts)
  - CVSS/CWE  : severity and vulnerability class

Then it writes artifacts seeded with that real data:
  - summary.md       : the triage, up top, so you know if you even care
  - sigma.yml        : detection rule, seeded from the CWE class + references
  - semgrep.yml      : a code-pattern rule for code-level CWEs (sqli, xss, rce, ...)
  - nuclei.yaml      : web-check template (for remote/web CVEs)
  - version-checks.sh: per-ecosystem "is the vulnerable package here?" commands
  - repro/           : a scaffold pinned to a vulnerable version

`--ai` drafts a concrete detection + repro from the whole enriched context via the
`claude` CLI (no API key).

    python3 cve2detect.py CVE-2021-44228
    python3 cve2detect.py CVE-2021-23337 --ai
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import urllib.parse
import urllib.request

UA = {"User-Agent": "cve2detect/0.2"}
EXPLOIT_HOSTS = ("exploit-db.com", "github.com", "packetstormsecurity", "metasploit",
                 "rapid7.com/db", "nuclei-templates", "0day.today", "seclists.org/fulldisclosure")

# CWE class -> (human label, is_code_pattern, what a detection should look for)
CWE_HINTS = {
    "CWE-79": ("Cross-site scripting", True, "untrusted input reflected into HTML/JS output without encoding"),
    "CWE-89": ("SQL injection", True, "untrusted input concatenated into a SQL query"),
    "CWE-78": ("OS command injection", True, "untrusted input passed to a shell/exec call"),
    "CWE-77": ("Command injection", True, "untrusted input in a command string"),
    "CWE-94": ("Code injection", True, "untrusted input reaching eval/compile/template render"),
    "CWE-95": ("Eval injection", True, "untrusted input reaching eval()"),
    "CWE-502": ("Deserialization of untrusted data", True, "untrusted bytes passed to a deserializer (pickle/yaml.load/ObjectInputStream)"),
    "CWE-22": ("Path traversal", True, "untrusted input used in a filesystem path without normalization"),
    "CWE-23": ("Path traversal", True, "untrusted input used in a filesystem path"),
    "CWE-918": ("SSRF", True, "untrusted input used as a request URL/host"),
    "CWE-611": ("XML external entity (XXE)", True, "XML parsed with external entities enabled"),
    "CWE-1321": ("Prototype pollution", True, "recursive merge/assign with attacker-controlled keys"),
    "CWE-434": ("Unrestricted file upload", True, "uploaded file written/executed without type checks"),
    "CWE-352": ("CSRF", False, "state-changing request without anti-CSRF token validation"),
    "CWE-287": ("Improper authentication", False, "auth check bypassable"),
    "CWE-306": ("Missing authentication", False, "sensitive function reachable without auth"),
    "CWE-862": ("Missing authorization", False, "action performed without authorization check"),
    "CWE-863": ("Incorrect authorization", False, "authorization decision is wrong"),
    "CWE-400": ("Uncontrolled resource consumption (DoS)", False, "input that triggers unbounded work/memory"),
    "CWE-20": ("Improper input validation", False, "input not validated before use"),
}

SEMGREP_LANG = {"PyPI": "python", "npm": "javascript", "Maven": "java", "Go": "go",
                "RubyGems": "ruby", "Packagist": "php", "crates.io": "generic"}


def get_json(url, timeout=20):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout) as r:
            return json.load(r)
    except Exception:
        return None


# ---------- fetch + enrich ----------

def fetch(cve):
    rec = {"id": cve, "summary": "", "cvss": None, "severity": "unknown", "cwes": [],
           "affected": [], "references": [], "exploit_refs": [],
           "kev": None, "epss": None}

    # OSV: package data (follow GHSA/etc. aliases; CVE record only has git ranges)
    osv = get_json(f"https://api.osv.dev/v1/vulns/{cve}")
    records = []
    if osv:
        rec["summary"] = osv.get("summary", "") or osv.get("details", "")[:300]
        rec["references"] = [r.get("url", "") for r in osv.get("references", [])]
        records.append(osv)
        for al in osv.get("aliases", []):
            if al.startswith(("GHSA", "PYSEC", "RUSTSEC", "GO-", "GSD")):
                sub = get_json(f"https://api.osv.dev/v1/vulns/{al}")
                if sub:
                    records.append(sub)
    seen = set()
    for r in records:
        if not rec["summary"]:
            rec["summary"] = r.get("summary", "")
        for a in r.get("affected", []):
            pkg = a.get("package")
            if not pkg:
                continue
            key = (pkg.get("ecosystem"), pkg.get("name"))
            if key in seen:
                continue
            introduced = fixed = None
            for rng in a.get("ranges", []):
                if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                    continue
                for ev in rng.get("events", []):
                    introduced = ev.get("introduced", introduced)
                    fixed = ev.get("fixed", fixed)
            versions = a.get("versions", [])
            vuln_example = next((v for v in reversed(versions) if v != fixed), None) or \
                (introduced if introduced not in (None, "0") else None)
            seen.add(key)
            rec["affected"].append({"ecosystem": pkg.get("ecosystem", ""), "name": pkg.get("name", ""),
                                    "introduced": introduced, "fixed": fixed, "vuln_example": vuln_example})

    # NVD: cvss, cwe, KEV (cisa* fields), reference tags (-> exploit signal)
    nvd = get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}")
    if nvd and nvd.get("vulnerabilities"):
        c = nvd["vulnerabilities"][0]["cve"]
        if not rec["summary"]:
            rec["summary"] = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        for w in c.get("weaknesses", []):
            for d in w.get("description", []):
                if d["value"].startswith("CWE-"):
                    rec["cwes"].append(d["value"])
        metrics = c.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                data = metrics[key][0]["cvssData"]
                rec["cvss"] = data.get("baseScore")
                rec["severity"] = (data.get("baseSeverity") or "").lower() or rec["severity"]
                break
        if c.get("cisaExploitAdd"):
            rec["kev"] = {"added": c["cisaExploitAdd"], "due": c.get("cisaActionDue"),
                          "action": c.get("cisaRequiredAction"), "name": c.get("cisaVulnerabilityName")}
        for r in c.get("references", []):
            url = r.get("url", "")
            if url and url not in rec["references"]:
                rec["references"].append(url)
            if "Exploit" in r.get("tags", []):
                rec["exploit_refs"].append(url)
    rec["cwes"] = sorted(set(rec["cwes"]))

    # references that point at known exploit sources
    for url in rec["references"]:
        if any(h in url for h in EXPLOIT_HOSTS) and url not in rec["exploit_refs"]:
            rec["exploit_refs"].append(url)

    # EPSS
    epss = get_json(f"https://api.first.org/data/v1/epss?cve={cve}")
    if epss and epss.get("data"):
        d = epss["data"][0]
        rec["epss"] = {"score": float(d["epss"]), "percentile": float(d["percentile"])}

    return rec if (osv or nvd) else None


def exploited_status(rec):
    if rec["kev"]:
        return "ACTIVELY EXPLOITED (on CISA KEV)"
    if rec["exploit_refs"]:
        return "public exploit referenced"
    return "no public exploit found in references"


def fetch_nuclei_template(cve):
    """Pull the real community detection from projectdiscovery/nuclei-templates, if one exists.
    These are working, vetted checks keyed by CVE id, so we ship the real thing instead of a skeleton."""
    year = cve.split("-")[1]
    base = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/main"
    for path in (f"http/cves/{year}/{cve}.yaml", f"cves/{year}/{cve}.yaml"):
        try:
            with urllib.request.urlopen(urllib.request.Request(f"{base}/{path}", headers=UA), timeout=15) as r:
                return r.read().decode(), path
        except Exception:
            continue
    return None, None


# ---------- generators ----------

def triage(rec):
    lines = [f"# {rec['id']}", ""]
    sev = rec["severity"].upper() if rec["severity"] != "unknown" else "?"
    lines.append(f"- **Severity:** {sev} (CVSS {rec['cvss']})")
    if rec["epss"]:
        lines.append(f"- **EPSS:** {rec['epss']['score']*100:.1f}% exploitation probability "
                     f"({rec['epss']['percentile']*100:.0f}th percentile of all CVEs)")
    lines.append(f"- **Exploitation:** {exploited_status(rec)}")
    if rec["kev"]:
        lines.append(f"    - KEV added {rec['kev']['added']}, remediate by {rec['kev']['due']}")
        if rec["kev"].get("action"):
            lines.append(f"    - required action: {rec['kev']['action']}")
    if rec.get("nuclei_template"):
        lines.append(f"- **Nuclei check:** real community template available ({rec['nuclei_template']})")
    if rec["cwes"]:
        labels = [f"{c} ({CWE_HINTS[c][0]})" if c in CWE_HINTS else c for c in rec["cwes"]]
        lines.append(f"- **Class:** {', '.join(labels)}")
    if rec["exploit_refs"]:
        lines.append("- **Exploit references:**")
        lines += [f"    - {u}" for u in rec["exploit_refs"][:4]]
    return "\n".join(lines)


def code_cwe(rec):
    return next((c for c in rec["cwes"] if c in CWE_HINTS and CWE_HINTS[c][1]), None)


def gen_semgrep(rec):
    cwe = code_cwe(rec)
    if not cwe:
        return None
    label, _, look_for = CWE_HINTS[cwe]
    lang = "generic"
    if rec["affected"]:
        lang = SEMGREP_LANG.get(rec["affected"][0]["ecosystem"], "generic")
    sev = "ERROR" if rec["severity"] in ("critical", "high") else "WARNING"
    return textwrap.dedent(f"""\
        rules:
          - id: {rec['id'].lower()}-{cwe.lower()}
            languages: [{lang}]
            severity: {sev}
            message: >
              {rec['id']} ({label}). Look for: {look_for}.
              {rec['summary'][:140]}
            metadata:
              cve: {rec['id']}
              cwe: {cwe}
              references:
{chr(10).join(f"                - {u}" for u in rec['references'][:4]) or "                - <add reference>"}
            # TODO: narrow to the vulnerable sink in {rec['affected'][0]['name'] if rec['affected'] else 'the affected code'}.
            # Pattern below is a CWE-class starting point for: {look_for}
            patterns:
              - pattern-either:
                  - pattern: $SINK(..., $UNTRUSTED, ...)
              # refine $SINK to the dangerous API and $UNTRUSTED to the tainted source
        """)


def gen_sigma(rec):
    refs = "\n".join(f"        - {u}" for u in rec["references"][:5]) or "        - <add reference>"
    level = rec["severity"] if rec["severity"] in ("critical", "high", "medium", "low") else "medium"
    cwe = code_cwe(rec) or (rec["cwes"][0] if rec["cwes"] else None)
    hint = CWE_HINTS.get(cwe, (None, None, "the exploited behavior"))[2] if cwe else "the exploited behavior"
    kev_note = "  (ON CISA KEV - actively exploited, prioritize)" if rec["kev"] else ""
    return textwrap.dedent(f"""\
        title: {rec['id']} - {(rec['summary'] or 'detection')[:66]}
        id: {rec['id'].lower()}-detect
        status: experimental
        description: |
            Detection for {rec['id']}.{kev_note}
            Hunt for: {hint}.
        references:
{refs}
        tags:
            - {rec['id'].lower()}
""" + "".join(f"            - cve.{rec['id'][4:]}\n" for _ in [0]) + textwrap.dedent(f"""\
        logsource:
            category: TODO      # process_creation | webserver | dns | network_connection
        detection:
            selection:
                TODO_field|contains:
                    - 'TODO_indicator'   # derive from the exploit reference above
            condition: selection
        level: {level}
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
          reference:
{refs}
          classification:
            cve-id: {rec['id']}
          tags: cve
        # TODO: fill the request + matcher from the PoC in the references.
        http:
          - method: GET
            path: ["{{{{BaseURL}}}}/TODO"]
            matchers:
              - type: word
                words: ["TODO_marker"]
        """)


VERCHECK = {"PyPI": "pip show {p}", "npm": "npm ls {p}", "crates.io": "cargo tree -i {p}",
            "Go": "govulncheck ./...", "Maven": "mvn dependency:tree | grep {n}",
            "RubyGems": "bundle list | grep {p}", "Packagist": "composer show {p}"}

REPRO = {
    "PyPI": lambda p, v: (("requirements.txt", f"{p}=={v or '<VULN>'}\n"),
                          ("run.sh", "#!/usr/bin/env bash\nset -e\npython3 -m venv .venv && . .venv/bin/activate\npip install -r requirements.txt\npython3 repro.py\n"),
                          ("repro.py", f"import {p.replace('-', '_')}  # TODO: call the vulnerable path\nprint('TODO: trigger')\n")),
    "npm": lambda p, v: (("package.json", json.dumps({"dependencies": {p: v or "<VULN>"}}, indent=2) + "\n"),
                         ("run.sh", "#!/usr/bin/env bash\nset -e\nnpm install\nnode index.js\n"),
                         ("index.js", f"const lib=require('{p}'); // TODO: call the vulnerable path\nconsole.log('TODO: trigger');\n")),
    "crates.io": lambda p, v: (("Cargo.toml", f'[package]\nname="repro"\nversion="0.1.0"\nedition="2021"\n[dependencies]\n{p}="={v or "<VULN>"}"\n'),
                               ("run.sh", "#!/usr/bin/env bash\nset -e\ncargo run\n"),
                               ("src/main.rs", f"fn main() {{ /* TODO: call vulnerable path in {p} */ println!(\"TODO\"); }}\n")),
}


def gen_repro(rec, outdir):
    if not rec["affected"]:
        return None
    a = rec["affected"][0]
    if a["ecosystem"] not in REPRO:
        return None
    rd = os.path.join(outdir, "repro")
    for name, content in REPRO[a["ecosystem"]](a["name"], a["vuln_example"]):
        path = os.path.join(rd, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        if name.endswith(".sh"):
            os.chmod(path, 0o755)
    return rd


def run_ai(rec, outdir):
    if not shutil.which("claude"):
        print("  --ai: `claude` CLI not found, skipping")
        return
    prompt = ("You are a detection engineer. Given this enriched CVE, write: (1) a concrete detection "
              "with the best data source and the exact indicators to match (derive from the CWE class and "
              "exploit references), and (2) a minimal repro outline. Be concrete and terse.\n\n"
              + json.dumps(rec, indent=2))
    try:
        r = subprocess.run(["claude", "-p", "--output-format", "text"], input=prompt,
                           capture_output=True, text=True, timeout=180)
        if r.returncode == 0 and r.stdout.strip():
            with open(os.path.join(outdir, "ai-draft.md"), "w") as f:
                f.write(f"# AI detection + repro draft for {rec['id']}\n\n{r.stdout}\n")
            print("  --ai: wrote ai-draft.md")
        else:
            print(f"  --ai: no output ({r.stderr.strip()[:80]})")
    except Exception as e:
        print(f"  --ai: skipped ({e})")


def main():
    ap = argparse.ArgumentParser(description="triage a CVE and bootstrap detection + repro")
    ap.add_argument("cve")
    ap.add_argument("--out", default="cve2detect-out")
    ap.add_argument("--ai", action="store_true", help="draft fuller artifacts via the claude CLI")
    args = ap.parse_args()
    cve = args.cve.upper()
    if not re.match(r"CVE-\d{4}-\d+$", cve):
        sys.exit("error: expected a CVE id like CVE-2021-44228")

    print(f"fetching + enriching {cve} (OSV, NVD, EPSS, KEV, nuclei-templates) ...")
    rec = fetch(cve)
    if not rec:
        sys.exit(f"error: {cve} not found in OSV or NVD")
    nuclei_real, nuclei_path = fetch_nuclei_template(cve)
    rec["nuclei_template"] = nuclei_path

    # print the triage banner to the terminal (the headline)
    print("\n" + triage(rec).replace("# ", "").replace("**", "").strip() + "\n")

    outdir = os.path.join(args.out, cve)
    os.makedirs(outdir, exist_ok=True)
    with open(os.path.join(outdir, "summary.md"), "w") as f:
        f.write(triage(rec))
        f.write("\n\n" + rec["summary"] + "\n")
        f.write("\n## Affected packages\n")
        if rec["affected"]:
            for a in rec["affected"]:
                intro = a["introduced"] if a["introduced"] not in (None, "0") else "earliest"
                f.write(f"- `{a['ecosystem']}:{a['name']}` introduced {intro}, fixed in {a['fixed'] or 'see advisory'}\n")
        else:
            f.write("- (no package-level data; likely an OS/appliance CVE)\n")
        f.write("\n## Generated\n- sigma.yml (seeded), "
                + ("nuclei.yaml (REAL community detection from nuclei-templates: " + nuclei_path + ")" if nuclei_path
                   else "nuclei.yaml (skeleton; no community template exists)")
                + ", version-checks.sh"
                + (", semgrep.yml" if code_cwe(rec) else "")
                + (", repro/" if (rec["affected"] and rec["affected"][0]["ecosystem"] in REPRO) else "") + "\n")
    with open(os.path.join(outdir, "sigma.yml"), "w") as f:
        f.write(gen_sigma(rec))
    with open(os.path.join(outdir, "nuclei.yaml"), "w") as f:
        f.write(nuclei_real if nuclei_real else gen_nuclei(rec))
    sg = gen_semgrep(rec)
    if sg:
        with open(os.path.join(outdir, "semgrep.yml"), "w") as f:
            f.write(sg)
    checks = []
    for a in rec["affected"]:
        t = VERCHECK.get(a["ecosystem"])
        if t:
            checks.append(f"# {a['ecosystem']}: {a['name']} (fixed {a['fixed'] or 'see advisory'})\n"
                          + t.format(p=a["name"], n=a["name"].split(":")[-1]))
    if checks:
        with open(os.path.join(outdir, "version-checks.sh"), "w") as f:
            f.write("#!/usr/bin/env bash\n# " + cve + "\n\n" + "\n\n".join(checks) + "\n")
    gen_repro(rec, outdir)
    if args.ai:
        run_ai(rec, outdir)

    print(f"wrote artifacts to {outdir}/")
    for n in sorted(os.listdir(outdir)):
        print(f"  {n}")


if __name__ == "__main__":
    main()
