# cve2detect

Triage a CVE and bootstrap detection + reproduction. Give it a CVE id; it pulls the
advisory from OSV + NVD and enriches it with the data a defender actually triages on,
then writes artifacts seeded with that data.

**Triage first (the headline):**
- **KEV** - is it on CISA's Known Exploited Vulnerabilities list (exploited in the wild)?
- **EPSS** - FIRST's probability it will be exploited in the next 30 days, with percentile.
- **public exploit?** - concrete sources: **Metasploit** modules (rapid7's module metadata),
  **Exploit-DB** entries (the exploitdb `codes` map), a real **Nuclei** template, and NVD
  exploit-tagged references.
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
- **`nuclei.yaml`** - the **real, community-maintained Nuclei detection** pulled from
  projectdiscovery/nuclei-templates when one exists (a working `nuclei -t nuclei.yaml -u <host>`
  check, not a skeleton); falls back to a seeded skeleton only when no template is published.
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

## The `--ai` flag (pluggable backends)
The deterministic core above needs no LLM. With `--ai`, cve2detect drafts a concrete
detection + repro into `ai-draft.md` using a backend of your choice:

```sh
python3 cve2detect.py CVE-2021-44228 --ai                                            # claude CLI (default, no key)
python3 cve2detect.py CVE-2021-44228 --ai --ai-backend ollama --ai-model qwen2.5:3b  # local model, no key
OPENAI_API_KEY=... python3 cve2detect.py CVE-2021-44228 --ai --ai-backend openai --ai-model gpt-4o
```

- **claude** (default) - the Claude Code CLI (`claude -p`), no API key.
- **ollama** - a local model (default `--ai-url http://localhost:11434`), no key, fully offline.
- **openai** - any OpenAI-compatible API (OpenAI, OpenRouter, Groq, a local llama.cpp server, ...);
  set `--ai-url` and `OPENAI_API_KEY` (or `AI_API_KEY`).

`--ai-model` and `--ai-url` override the per-backend defaults; missing key/server is skipped with a clear message.

## Honest scope
The generated rules are **seeded skeletons, not finished detections** - they give you the
real metadata, the right format, and a starting structure so you are not writing boilerplate
from a blank file. The version checks and the repro pin are concrete. `--ai` drafts the rest.

## Requirements
Python 3 (stdlib only). Network access for OSV + NVD. The `claude` CLI is optional, only for `--ai`.

## Roadmap
- richer code-pattern rules (Semgrep) when the CWE/PoC implies a code signature
- derive a Nuclei matcher from a referenced PoC when no community template exists
