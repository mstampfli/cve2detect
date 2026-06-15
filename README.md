# cve2detect

Triage a CVE and bootstrap detection + reproduction. Give it a CVE id; it pulls the
advisory from OSV + NVD and enriches it with the data a defender actually triages on,
then writes artifacts seeded with that data.

**Triage first (the headline):**
- **KEV** - is it on CISA's Known Exploited Vulnerabilities list (exploited in the wild)?
- **EPSS** - FIRST's probability it will be exploited in the next 30 days, with percentile.
- **public exploit?** - derived from NVD reference tags and known exploit hosts.
- **CVSS / CWE** - severity and vulnerability class.

So before you write a line of detection, you know whether you even need to.

```
python3 cve2detect.py CVE-2021-44228
python3 cve2detect.py CVE-2021-23337 --ai
```

## What it generates
Into `cve2detect-out/<CVE>/`:
- **`sigma.yml`** - a Sigma detection-rule skeleton seeded with the title, references, CWE
  tags, and a severity-mapped level. You fill in the log source and indicators.
- **`nuclei.yaml`** - a Nuclei web-check template skeleton (for web/exploit-style CVEs).
- **`version-checks.sh`** - per-ecosystem commands to find the vulnerable package in a
  project (npm/pip/cargo/go/maven/...), with the fixed version noted.
- **`repro/`** - a minimal scaffold pinned to a vulnerable version (npm / PyPI / crates.io),
  with a `run.sh` and a TODO trigger.
- **`semgrep.yml`** - for code-level CWEs (SQLi, XSS, RCE, deserialization, path traversal,
  SSRF, ...), a language-specific Semgrep rule with the CWE-class "what to look for" baked in.
- **`summary.md`** - the full triage (KEV/EPSS/exploit/CVSS/CWE) plus affected packages and references.

## How it resolves package data
OSV's CVE-level record usually only has git-commit ranges, so cve2detect follows the
GHSA / PYSEC / RUSTSEC aliases to get the real ecosystem packages and version ranges, and
pulls CVSS + CWE from NVD. Example: `CVE-2021-44228` resolves to
`Maven:org.apache.logging.log4j:log4j-core`, introduced 2.13.0, fixed 2.15.0.

## The `--ai` flag
The deterministic core above needs no LLM. With `--ai`, it pipes the structured CVE data to
the `claude` CLI (`claude -p`) and writes `ai-draft.md` with a fuller, concrete detection
idea and a repro outline. No API key required; it uses your Claude Code login. If `claude`
isn't installed, it just skips that step.

## Honest scope
The generated rules are **seeded skeletons, not finished detections** - they give you the
real metadata, the right format, and a starting structure so you are not writing boilerplate
from a blank file. The version checks and the repro pin are concrete. `--ai` drafts the rest.

## Requirements
Python 3 (stdlib only). Network access for OSV + NVD. The `claude` CLI is optional, only for `--ai`.

## Roadmap
- richer code-pattern rules (Semgrep) when the CWE/PoC implies a code signature
- KEV (known-exploited) enrichment and EPSS scoring
- pull a real PoC from the references to auto-fill the Nuclei matcher
