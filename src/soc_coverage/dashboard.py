"""Optional Streamlit dashboard for interactive local analysis."""
from __future__ import annotations

import json

import streamlit as st

from soc_coverage.attack import load_attack
from soc_coverage.coverage import analyze, load_declared_sources
from soc_coverage.wazuh_parser import parse_rules_dir


def main() -> None:
    st.set_page_config(page_title="SOC Coverage Analyzer", layout="wide")
    st.title("AI-Assisted SOC Coverage Analyzer")
    st.caption("Deterministic coverage first; AI drafts are optional and always require human review.")
    attack_path = st.text_input("ATT&CK STIX JSON", "data/enterprise-attack.json")
    rules_path = st.text_input("Wazuh rules directory", "data/wazuh_rules")
    config_path = st.text_input("Declared log sources YAML", "config/log_sources.example.yaml")
    mapping_path = st.text_input("Log source mapping YAML", "config/logsource_mapping.yaml")
    if not st.button("Analyze"):
        return
    try:
        attack = load_attack(attack_path)
        declared = load_declared_sources(config_path, mapping_path)
        report = analyze(parse_rules_dir(rules_path), attack, declared)
    except (OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        st.error(str(exc))
        return
    counts = {}
    for result in report.results.values():
        counts[result.status] = counts.get(result.status, 0) + 1
    st.metric("Techniques analyzed", len(report.results))
    st.json(counts)
    rows = [
        {"Technique": f"{r.attack_id} {r.name}", "Status": r.status,
         "Rules": ", ".join(r.rule_ids), "Matching sources": ", ".join(r.matching_log_sources)}
        for r in report.results.values() if r.status != "no_guidance"
    ]
    st.dataframe(rows, use_container_width=True)


if __name__ == "__main__":
    main()
