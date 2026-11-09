from __future__ import annotations

import re
from datetime import date

from .attack import AttackData
from .coverage import COVERED, NO_GUIDANCE, OBSERVABLE, TELEMETRY, CoverageReport, summarize, top_candidate_gaps


_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _diagnostic_unknown_techniques(report: CoverageReport) -> dict[str, list[str]]:
    """Filter non-technique metadata from the rule-to-ATT&CK mismatch report."""
    filtered: dict[str, list[str]] = {}
    for tid, rule_ids in report.unknown_technique_ids.items():
        clean = tid.strip()
        if clean == "$(THREAT.SOFTWARE.ID)":
            continue
        if re.fullmatch(r"TA\d{4}", clean):
            continue
        if _TECHNIQUE_ID_RE.fullmatch(clean):
            filtered[clean] = rule_ids
    return filtered


def to_markdown(report: CoverageReport, attack: AttackData, declared: dict[str, list[str]]) -> str:
    parents = [r for t, r in report.results.items() if not attack.techniques[t].is_subtechnique]
    cnt = lambda s: sum(1 for r in parents if r.status == s)  # noqa: E731
    lines = [
        "# SOC detection coverage report",
        f"_Generated {date.today().isoformat()} - ATT&CK Enterprise v{report.attack_version}_",
        "",
        f"- Wazuh rules analysed: **{report.rules_total}** ({report.rules_with_mitre} declare a MITRE technique)",
        f"- Declared log sources: {', '.join(declared) or 'none'}",
        "",
        "## Summary (parent techniques)",
        f"| Status | Count |\n|---|---|\n| Covered by a rule | {cnt(COVERED)} |\n"
        f"| Candidate gap (observable with your logs) | {cnt(OBSERVABLE)} |\n"
        f"| Telemetry gap (needs new logs) | {cnt(TELEMETRY)} |\n"
        f"| No ATT&CK guidance (not judged) | {cnt(NO_GUIDANCE)} |",
        "",
        "> **Read this carefully.** 'Covered' is a static rule-to-technique mapping, not proof that the rule "
        "fires. 'Candidate gap' means a detection *could* be built from data you already collect; it is not "
        "a confirmed blind spot until validated.",
        "",
        "## Per tactic (parent techniques)",
        "| Tactic | Covered | Candidate gap | Telemetry gap |",
        "|---|---|---|---|",
    ]
    for tac, c in sorted(summarize(report, attack, only_parents=True).items()):
        lines.append(f"| {attack.tactics.get(tac, tac)} | {c[COVERED]} | {c[OBSERVABLE]} | {c[TELEMETRY]} |")
    lines += ["", "## Top candidate gaps", "| Technique | Tactic | Usable log sources |", "|---|---|---|"]
    for g in top_candidate_gaps(report, attack, 15):
        lines.append(f"| {g.attack_id} {g.name} | {', '.join(g.tactics)} | {', '.join(g.matching_log_sources)} |")
    unknown = _diagnostic_unknown_techniques(report)
    if unknown:
        lines += ["", "## Technique IDs in rules but not in this ATT&CK version",
                  *[f"- {t}: rules {', '.join(r)}" for t, r in sorted(unknown.items())]]
    return "\n".join(lines) + "\n"


def to_html(report: CoverageReport, attack: AttackData, declared: dict[str, list[str]]) -> str:
    """Render a self-contained HTML report for sharing without a web server."""
    md = to_markdown(report, attack, declared)
    escaped = md.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>SOC coverage report</title>
<style>body{{font:16px system-ui,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem}}
pre{{white-space:pre-wrap;background:#f6f8fa;padding:1rem;border-radius:6px}}
h1{{color:#172b4d}}</style></head>
<body><h1>SOC detection coverage report</h1><pre>{escaped}</pre></body></html>"""
