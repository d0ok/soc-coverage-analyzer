# SOC Coverage Analyzer

**An offline-friendly SOC detection coverage analyzer for Wazuh and MITRE ATT&CK Enterprise.**

SOC Coverage Analyzer compares Wazuh rules with MITRE ATT&CK Enterprise techniques and the log sources declared by a SOC.

It produces:

- deterministic ATT&CK technique coverage results;
- candidate detection gaps;
- telemetry gaps;
- ATT&CK Navigator layers;
- Markdown and HTML reports;
- optional local LLM recommendations using Ollama.

The LLM does not decide whether a technique is covered. Coverage and gap classification remain deterministic.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Coverage Classification](#coverage-classification)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Fetch ATT&CK and Wazuh Data](#fetch-attck-and-wazuh-data)
- [Run the Analyzer](#run-the-analyzer)
- [Generated Outputs](#generated-outputs)
- [Streamlit Dashboard](#streamlit-dashboard)
- [Local AI Recommendations with Ollama](#local-ai-recommendations-with-ollama)
- [ATT&CK Navigator Integration](#attck-navigator-integration)
- [Testing](#testing)
- [Example Results](#example-results)
- [Limitations](#limitations)
- [Offline Operation](#offline-operation)
- [Project Status](#project-status)

---

## Overview

Security Operations Centers often have detection rules and log sources, but it can be difficult to understand how those capabilities align with MITRE ATT&CK.

SOC Coverage Analyzer addresses this by combining:

1. **Wazuh XML rules**  
   Existing MITRE technique identifiers are extracted from Wazuh rules instead of being guessed by an LLM.

2. **MITRE ATT&CK Enterprise STIX data**  
   Techniques, sub-techniques, tactics, data components, and detection guidance are loaded from ATT&CK data.

3. **Declared SOC log sources**  
   A YAML configuration describes the log sources that are actually available in the environment.

4. **Deterministic coverage analysis**  
   Each technique is classified as covered, observable with current telemetry, a telemetry gap, or not judged because ATT&CK does not provide sufficient guidance.

5. **Optional LLM recommendations**  
   Ollama can draft detection ideas for the highest-priority candidate gaps. Recommendations are validated and always marked for human review.

---

## Features

- Parse Wazuh XML rules.
- Extract existing MITRE ATT&CK technique identifiers.
- Resolve known revoked or deprecated ATT&CK technique identifiers where replacement relationships exist.
- Load ATT&CK Enterprise STIX data.
- Load declared SOC log sources from YAML.
- Map ATT&CK data components to declared log sources.
- Classify technique coverage deterministically.
- Export ATT&CK Navigator layer JSON.
- Generate Markdown and HTML reports.
- Generate structured recommendation output.
- Use Ollama for local LLM inference.
- Validate LLM responses with Pydantic.
- Reject recommendations that cite undeclared log sources.
- Mark every accepted recommendation as requiring human review.
- Fall back to deterministic recommendations when AI is unavailable.
- Provide an optional Streamlit dashboard.
- Support offline fixture-based analysis.

---

## Coverage Classification

The analyzer uses four statuses.

| Status | Meaning |
|---|---|
| `covered` | At least one Wazuh rule explicitly declares the ATT&CK technique. This is a static mapping and does not prove that the rule fires correctly. |
| `observable_gap` | No mapped Wazuh rule exists, but the declared log sources match ATT&CK data-component or log-source guidance. This is a candidate detection gap. |
| `telemetry_gap` | No mapped Wazuh rule exists and the current declared log sources do not match the available ATT&CK guidance. Additional telemetry may be required. |
| `no_guidance` | ATT&CK does not provide enough detection or data-source guidance for the analyzer to make a useful classification. |

### Important interpretation

The analyzer does not test whether:

- a Wazuh rule fires correctly;
- an event is actually being collected;
- a data source is complete or correctly configured;
- a detection has acceptable false-positive rates;
- a candidate gap is exploitable in the analyzed environment.

The results are a prioritization aid for analysts, not proof of operational detection coverage.

---

## Architecture

```text
                    INPUTS
                       |
        +--------------+--------------+
        |              |              |
    Wazuh XML      ATT&CK STIX     Log-source YAML
      rules          dataset        and mappings
        |              |              |
        +--------------+--------------+
                       |
                       v
              Parsing and normalization
                       |
        +--------------+--------------+
        |                             |
   Wazuh MITRE IDs              ATT&CK techniques,
   and rule metadata             tactics and data
                                 components
        |                             |
        +--------------+--------------+
                       |
                       v
              Deterministic coverage
                 and gap analysis
                       |
        +--------------+--------------+
        |              |              |
     Covered     Candidate gap    Telemetry gap
        |              |              |
        +--------------+--------------+
                       |
                       v
                    OUTPUTS
        +--------------+--------------+
        |              |              |
   Navigator       Markdown/HTML   JSON results
     layer            reports
                                      |
                                      v
                         Optional recommendation layer
                                      |
                         +------------+------------+
                         |                         |
                       Ollama              Deterministic fallback
                         |                         |
                         +------------+------------+
                                      |
                         Pydantic validation and
                         declared-source guardrail
                                      |
                              Human review required
```

Coverage classification is deterministic and does not depend on an LLM.

---

## Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core implementation |
| XML | Wazuh rule parsing |
| YAML | Log-source configuration |
| MITRE ATT&CK Enterprise | Technique, tactic, and detection guidance |
| STIX JSON | ATT&CK data format |
| Pydantic | Structured recommendation validation |
| Ollama | Optional local LLM inference |
| Llama 3.2 3B | Example local model |
| Streamlit | Optional dashboard |
| ATT&CK Navigator | Coverage visualization |
| Markdown and HTML | Human-readable reports |
| Pytest | Automated tests |

---

## Project Structure

```text
soc-coverage-analyzer/
├── config/
│   ├── log_sources.example.yaml
│   └── logsource_mapping.yaml
├── examples/
│   ├── attack-fixture.json
│   └── ...
├── src/
│   └── soc_coverage/
│       ├── attack.py
│       ├── attack_ids.py
│       ├── cli.py
│       ├── coverage.py
│       ├── dashboard.py
│       ├── recommend.py
│       ├── report.py
│       └── wazuh_parser.py
├── tests/
│   └── test_core.py
├── pyproject.toml
├── README.md
└── output/
    └── generated locally
```

The following directories are generated locally and should not normally be committed:

```text
.venv/
data/
output/
```

The downloaded ATT&CK dataset and Wazuh rules are intentionally kept outside the source package because they can be large and change over time.

---

## Requirements

- Python 3.10 or newer.
- Git.
- Internet access for fetching live ATT&CK and Wazuh data.
- Ollama and a local model for optional AI recommendations.
- Streamlit for the optional dashboard.

The deterministic analyzer and fixture-based tests do not require an LLM.

---

## Installation

### 1. Clone the repository

```powershell
git clone https://github.com/d0ok/soc-coverage-analyzer.git
cd soc-coverage-analyzer
```

### 2. Create and activate a virtual environment

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, use the project interpreter directly:

```powershell
.\.venv\Scripts\python.exe
```

### 3. Upgrade pip

```powershell
python -m pip install --upgrade pip
```

### 4. Install the project

Install the package and development dependencies:

```powershell
pip install -e ".[dev]"
```

Install the optional dashboard:

```powershell
pip install -e ".[dashboard]"
```

The CLI should now be available:

```powershell
soc-coverage --help
```

If the console command is not available, use the module form:

```powershell
py -3 -m soc_coverage --help
```

---

## Fetch ATT&CK and Wazuh Data

Fetch the current ATT&CK Enterprise STIX dataset and Wazuh rules:

```powershell
soc-coverage fetch
```

Equivalent module invocation:

```powershell
py -3 -m soc_coverage fetch
```

The command creates:

```text
data/
├── enterprise-attack.json
└── wazuh_rules/
    └── *.xml
```

The Wazuh fetch implementation:

- uses the GitHub API when available;
- falls back to a sparse Git clone;
- pins Wazuh retrieval to the `master` branch;
- downloads the XML rule files under `data/wazuh_rules`.

This command requires network access.

---

## Run the Analyzer

### Offline fixture analysis

The repository includes a small fixture for deterministic testing:

```powershell
soc-coverage analyze `
  --rules examples `
  --attack examples\attack-fixture.json `
  --config config\log_sources.example.yaml `
  --mapping config\logsource_mapping.yaml `
  --out output `
  --no-ai
```

### Real Wazuh and ATT&CK analysis

After running `soc-coverage fetch`:

```powershell
soc-coverage analyze `
  --rules data\wazuh_rules `
  --attack data\enterprise-attack.json `
  --config config\log_sources.example.yaml `
  --mapping config\logsource_mapping.yaml `
  --out output `
  --no-ai
```

The shorter configuration-based command is also supported:

```powershell
soc-coverage analyze --config config\log_sources.example.yaml
```

### Analysis with optional AI recommendations

Configure Ollama as described below, then run:

```powershell
soc-coverage analyze `
  --rules data\wazuh_rules `
  --attack data\enterprise-attack.json `
  --config config\log_sources.example.yaml `
  --mapping config\logsource_mapping.yaml `
  --out output
```

### Configuration files

| File | Purpose |
|---|---|
| `config/log_sources.example.yaml` | Declares the log sources available to the SOC |
| `config/logsource_mapping.yaml` | Maps declared sources to ATT&CK data components and source names |
| `examples/attack-fixture.json` | Small offline ATT&CK fixture for tests and demonstrations |

Edit the example YAML files to match the actual environment being analyzed.

---

## Generated Outputs

The analyzer writes these files to the selected output directory.

| File | Description |
|---|---|
| `coverage.json` | Per-technique classifications, rule references, tactics, and telemetry matches |
| `navigator_layer.json` | ATT&CK Navigator-compatible coverage layer |
| `report.md` | Human-readable Markdown report |
| `report.html` | Human-readable HTML report |
| `recommendations.json` | AI-generated or deterministic recommendation drafts |

### `coverage.json`

Contains structured results for each analyzed technique, including:

- technique ID;
- technique name;
- tactics;
- classification status;
- matching rule IDs;
- matching log sources;
- data-component information.

### `navigator_layer.json`

Contains an ATT&CK Navigator layer with colors and comments describing coverage state.

The generated layer uses:

- green for rule-covered techniques;
- orange for candidate gaps;
- grey for telemetry gaps.

### `report.md` and `report.html`

Summarize:

- total rules analyzed;
- rules with MITRE references;
- counts by coverage status;
- coverage by tactic;
- top candidate gaps;
- relevant diagnostic information.

### `recommendations.json`

Contains structured recommendation drafts.

Accepted recommendations include:

```json
{
  "technique_id": "T1110.002",
  "detection_idea": "...",
  "required_log_sources": [
    "WinEventLog:Security"
  ],
  "suggested_test": "...",
  "false_positive_notes": "...",
  "needs_human_review": true
}
```

The generated recommendations are not production-ready detections.

---

## Streamlit Dashboard

Install the dashboard dependency:

```powershell
pip install -e ".[dashboard]"
```

Run the dashboard from the repository root:

```powershell
python -m streamlit run src\soc_coverage\dashboard.py
```

If the `streamlit` command is available, this also works:

```powershell
streamlit run src\soc_coverage\dashboard.py
```

Open the URL displayed by Streamlit, normally:

```text
http://localhost:8501
```

The dashboard allows local review of:

- ATT&CK STIX input;
- Wazuh rules directory;
- declared log sources;
- log-source mappings;
- technique coverage statuses;
- matching rules and telemetry sources.

The dashboard is intended for local review and demonstrations, not production deployment.

---

## Local AI Recommendations with Ollama

The AI layer is optional.

It drafts recommendations only for candidate gaps identified by the deterministic analyzer. It does not decide whether a technique is covered.

### Why Ollama?

Ollama allows local inference without requiring an Anthropic API key or a hosted LLM service.

Advantages include:

- local model execution;
- no per-request hosted API charge;
- SOC data remains on the local machine;
- simple local HTTP API;
- ability to test the AI layer offline from cloud providers.

Local inference still requires sufficient memory, CPU, and disk space. Model licenses and capabilities vary.

### 1. Install Ollama

Download Ollama for Windows:

```text
https://ollama.com/download/windows
```

Verify the installation:

```powershell
ollama --version
```

### 2. Download a model

Run this from any directory:

```powershell
ollama pull llama3.2:3b
```

Verify that the model is installed:

```powershell
ollama list
```

Ollama normally provides its local API at:

```text
http://localhost:11434
```

### 3. Configure the provider

In PowerShell:

```powershell
$env:SOC_LLM_PROVIDER = "ollama"
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_BASE_URL = "http://localhost:11434"
```

These variables apply to the current PowerShell session.

### 4. Test Ollama directly

```powershell
Invoke-RestMethod `
  -Uri http://localhost:11434/api/generate `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"model":"llama3.2:3b","prompt":"Return only JSON: {\"ok\": true}","format":"json","stream":false}'
```

The response should contain a JSON object with a `response` field.

### 5. Run the analyzer

```powershell
soc-coverage analyze --config config\log_sources.example.yaml
```

Inspect the recommendations:

```powershell
Get-Content output\recommendations.json
```

### Provider behavior

| Configuration | Behavior |
|---|---|
| `SOC_LLM_PROVIDER=ollama` | Uses the local Ollama `/api/generate` endpoint |
| `SOC_LLM_PROVIDER=anthropic` | Uses the optional Anthropic integration when configured |
| No working AI provider | Uses deterministic recommendation drafts |
| `--no-ai` | Disables AI recommendation generation |

No API key is required for the local Ollama provider.

### Recommendation validation

Recommendations are validated using Pydantic and must include:

| Field | Requirement |
|---|---|
| `technique_id` | Must match the candidate ATT&CK technique |
| `detection_idea` | Non-empty detection proposal |
| `required_log_sources` | One or more declared log sources |
| `suggested_test` | A validation or simulation test |
| `false_positive_notes` | Optional tuning guidance |
| `needs_human_review` | Always forced to `true` |

### Guardrails

The recommendation layer:

1. Sends only candidate gaps to the LLM.
2. Includes the technique context and available log sources in the prompt.
3. Requires structured JSON output.
4. Validates the response with Pydantic.
5. Rejects malformed responses.
6. Rejects recommendations that cite undeclared log sources.
7. Forces `needs_human_review` to `true`.
8. Falls back to a deterministic draft if the LLM is unavailable.

Do not treat an LLM recommendation as a validated detection rule. Review and test it before implementation.

---

## ATT&CK Navigator Integration

The analyzer generates:

```text
output\navigator_layer.json
```

To import the layer:

1. Open MITRE ATT&CK Navigator.
2. Choose the option to import a layer.
3. Select `output\navigator_layer.json`.
4. Review the color-coded coverage results.

ATT&CK Navigator:

```text
https://github.com/mitre-attack/attack-navigator
```

The layer description explains the generated color meanings.

---

## Testing

Run the test suite:

```powershell
pytest -q
```

Equivalent module invocation:

```powershell
py -3 -m pytest -q
```

The tests cover:

- Wazuh MITRE ID extraction;
- three-state coverage classification;
- unknown technique diagnostics;
- ATT&CK revoked-ID replacement handling;
- data-component observability;
- Wazuh fetch branch pinning;
- Ollama response validation;
- malformed and undeclared-source recommendations;
- deterministic fallback behavior.

The latest validated test run completed with:

```text
12 passed
```

---

## Example Results

The following values come from a validated run using the downloaded Wazuh ruleset, ATT&CK Enterprise data, and the example declared log sources.

They are examples, not guarantees for another environment.

| Metric | Example result |
|---|---:|
| Wazuh rules analyzed | 4,420 |
| Rules declaring a MITRE technique | 1,046 |
| Covered parent techniques | 80 |
| Candidate gaps | 87 |
| Telemetry gaps | 50 |

The report also includes per-tactic summaries and a list of the highest-priority candidate gaps.

For example, candidate gaps may include techniques such as:

- Drive-by Compromise;
- Trusted Relationship;
- Hardware Additions;
- Wi-Fi Networks;
- Password Cracking;
- Password Spraying;
- Credential Stuffing.

These results depend on:

- the exact Wazuh ruleset version;
- the ATT&CK STIX version;
- the declared log sources;
- the log-source mapping configuration;
- the technique normalization and replacement data.

---

## Limitations

- **Static rule mapping:** A rule mapped to a technique does not prove that the rule fires, detects the intended behavior, or has been validated in production.
- **Telemetry declarations:** Declared log sources are configuration claims. The analyzer does not independently verify that events are collected, parsed, retained, or searchable.
- **ATT&CK guidance:** ATT&CK data components and analytics provide guidance, not a guarantee of observability.
- **Candidate gaps:** An observable candidate gap means that a detection may be possible with available telemetry. It is not automatically a confirmed blind spot.
- **Telemetry gaps:** A telemetry gap means that the configured mappings did not identify suitable current telemetry. It does not prove that no alternative data source exists.
- **ATT&CK versions:** ATT&CK techniques change over time. Revoked and deprecated IDs are resolved where replacement relationships are available, but unknown legacy values may remain.
- **Log-source mappings:** The example mappings are not universal. They must be reviewed for the actual environment.
- **AI recommendations:** LLM output can be incomplete, incorrect, or overly broad. Every recommendation requires human review and testing.
- **False positives:** The analyzer does not measure alert quality, precision, recall, or operational workload.
- **Framework scope:** The project currently focuses on MITRE ATT&CK Enterprise.
- **Dashboard scope:** The Streamlit dashboard is intended for local analysis and demonstrations.
- **Security and privacy:** Do not send sensitive SOC data to hosted providers unless the provider, account, and data-handling terms are appropriate for the environment.

---

## Offline Operation

The project supports several offline workflows.

### Fully offline fixture analysis

```powershell
soc-coverage analyze `
  --rules examples `
  --attack examples\attack-fixture.json `
  --config config\log_sources.example.yaml `
  --mapping config\logsource_mapping.yaml `
  --out output `
  --no-ai
```

### Offline analysis using already-downloaded data

Once the ATT&CK and Wazuh data exist under `data/`, analysis can run without fetching new data:

```powershell
soc-coverage analyze `
  --rules data\wazuh_rules `
  --attack data\enterprise-attack.json `
  --config config\log_sources.example.yaml `
  --mapping config\logsource_mapping.yaml `
  --out output `
  --no-ai
```

### Network-dependent operation

Only the fetch operation requires live network access:

```powershell
soc-coverage fetch
```

### Local AI operation

Ollama runs locally and does not require a hosted API key:

```powershell
$env:SOC_LLM_PROVIDER = "ollama"
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_BASE_URL = "http://localhost:11434"
```

---

## Project Status

This repository is an MVP for ATT&CK coverage analysis and detection-gap prioritization.

The deterministic analysis pipeline is the primary source of truth. The local AI layer is an optional assistant for drafting detection ideas, not an autonomous detection-engineering system.

Current validated capabilities include:

- real Wazuh rule ingestion;
- real ATT&CK Enterprise STIX loading;
- ATT&CK technique coverage classification;
- candidate-gap and telemetry-gap analysis;
- ATT&CK Navigator export;
- Markdown and HTML reports;
- local Ollama recommendation generation;
- Pydantic response validation;
- undeclared-log-source rejection;
- mandatory human-review labeling;
- Streamlit dashboard;
- automated tests.

---

## License

See the repository license file for applicable licensing terms.
