# SOC Coverage Analyzer

An offline-friendly MVP for comparing Wazuh rules against MITRE ATT&CK Enterprise and the log sources a SOC actually collects. It deterministically classifies coverage, emits ATT&CK Navigator JSON, generates markdown/HTML reports, and can draft candidate-gap recommendations with a strict human-review gate.

## What it answers

| Status | Meaning |
|---|---|
| `covered` | A rule declares the technique; static mapping only, not proof the rule fires. |
| `observable_gap` | No rule exists, but declared telemetry matches ATT&CK log sources or data components. |
| `telemetry_gap` | No rule exists and the current telemetry does not match ATT&CK guidance. |
| `no_guidance` | ATT&CK provides no useful detection or log-source guidance, so it is not treated as a gap. |

## Python / venv setup

On Windows:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install -e .
```

The project is structured as a package in `src/soc_coverage`, and the CLI entry point is:

```powershell
soc-coverage --help
```

## Fetch real Wazuh and ATT&CK data

To download current ATT&CK STIX and the Wazuh ruleset into `data/`:

```powershell
soc-coverage fetch
```

This writes:

- `data/enterprise-attack.json`
- `data/wazuh_rules/*.xml`

The fetch layer is intentionally network-aware: it uses the GitHub API when available and falls back to a sparse Git clone for the Wazuh repo. The Wazuh contents URL and sparse clone are pinned to the `master` branch.

## Run an analyze pass

Using the included example config and sample fixture:

```powershell
soc-coverage analyze --rules examples --attack examples/attack-fixture.json --config config\log_sources.example.yaml --mapping config\logsource_mapping.yaml --out output --no-ai
```

For a real local dataset:

```powershell
soc-coverage analyze --rules data\wazuh_rules --attack data\enterprise-attack.json --config config\log_sources.example.yaml --mapping config\logsource_mapping.yaml --out output --no-ai
```

The CLI writes the following outputs to the selected output directory:

- `coverage.json`
- `navigator_layer.json`
- `report.md`
- `report.html`
- `recommendations.json`

## Output and report files

The generated outputs are:

- `coverage.json`: per-technique classification and telemetry matches
- `navigator_layer.json`: ATT&CK Navigator layer JSON importable from the Navigator UI
- `report.md` and `report.html`: human-readable summary of coverage, gaps, and candidate detections
- `recommendations.json`: structured AI or deterministic recommendation drafts for top candidate gaps

## Streamlit dashboard

Install the optional dashboard dependency and run the UI:

```powershell
pip install -e ".[dashboard]"
streamlit run src\soc_coverage\dashboard.py
```

The dashboard reads the same coverage and recommendation artifacts and is intended for local review and walkthroughs rather than production deployment.

## Local Ollama AI setup

The AI layer is optional and never chooses whether a technique is covered. It only drafts detection ideas for candidate gaps after deterministic gap analysis has already identified them.

For local Ollama:

```powershell
$env:SOC_LLM_PROVIDER = "ollama"
$env:OLLAMA_MODEL = "llama3.2:3b"
$env:OLLAMA_BASE_URL = "http://localhost:11434"
```

Then run:

```powershell
soc-coverage analyze --rules data\wazuh_rules --attack data\enterprise-attack.json --config config\log_sources.example.yaml --mapping config\logsource_mapping.yaml --out output
```

Provider behavior:

- `ollama`: uses local `/api/generate` JSON mode
- `anthropic`: uses the Anthropic client when available
- no configured provider/API: the tooling falls back to deterministic offline drafts
- no secret or API-key setup is required for the default deterministic path

The recommendation payload is Pydantic-validated and must include:

- `technique_id`
- `detection_idea`
- `required_log_sources`
- `suggested_test`
- `needs_human_review` always set to `true`

The guardrail rejects any recommendation that cites a log source not declared in the local config, and any accepted list is always marked for analyst review.

## Example result (labeled example only)

The following numbers are an example run from a representative local dataset and should not be treated as a guarantee for your environment:

- 4420 total Wazuh rules
- 1046 rules mapped to MITRE ATT&CK
- 80 covered techniques
- 87 candidate gaps
- 50 telemetry gaps

This kind of output is intended to show the shape of the report; your actual results depend on the exact Wazuh rules, ATT&CK STIX version, and declared log sources in your environment.

## Import ATT&CK Navigator layer

Open MITRE ATT&CK Navigator and import the generated layer file:

- `output/navigator_layer.json`

The Navigator file is a standard ATT&CK layer JSON representation built from the analyzer's findings.

## Architecture diagram

```text
Wazuh XML rules + declared log sources
                 |
                 v
       wazuh parser / ATT&CK loader
                 |
                 v
    deterministic coverage and gap classification
       /                    \
      /                      \
     v                        v
Navigator JSON         Markdown / HTML report
     |                        |
     |                        v
     |               recommendation drafts
     |                        |
     +----> human review gate <----+
                 |
                 v
     AI suggestions (optional) or deterministic fallback
```

## Limitations and caveats

- The analyzer is a static mapping tool; it shows what a rule or telemetry source could plausibly support, not whether a rule works in production.
- ATT&CK data is versioned and may include deprecated or revoked IDs; the loader resolves known replacements where possible, but some legacy or unknown placeholders may still appear in the output.
- ATT&CK analytics are guidance, not an assurance of coverage or efficacy.
- Log-source mapping is environment-specific and requires local review; mismatches or false positives are still possible.
- AI-generated content is advisory only and requires human review before action.
- The project intentionally models Enterprise ATT&CK rather than all adversary frameworks.

## Notes for offline and local use

- The included example fixture runs fully offline without external network access.
- `soc-coverage fetch` is the only command that requires network access to retrieve live ATT&CK and Wazuh content.
- For CI, tests, or local analysis without a live LLM, run with `--no-ai` or leave the AI layer unset.
- Example config files live under `config/` and are intended to be edited to match your environment.
