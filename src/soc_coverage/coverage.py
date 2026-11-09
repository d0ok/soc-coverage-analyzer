"""Core analysis: classify every ATT&CK technique as covered / observable gap / telemetry gap.

Statuses (the important design point: an unmapped technique is NOT automatically a gap):
  covered         at least one Wazuh rule declares this technique (static mapping only;
                  it does not prove the rule fires correctly - validate it).
  observable_gap  no rule, but at least one declared log source can feed an ATT&CK analytic
                  for it -> a detection could be written with data you already collect.
  telemetry_gap   no rule, and none of the declared log sources feed an analytic for it
                  -> you would need new telemetry first.
  no_guidance     no rule and ATT&CK publishes no analytic/log source for it -> unknown,
                  not reported as a gap.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from pathlib import Path

import yaml

from .attack import AttackData
from .wazuh_parser import WazuhRule

COVERED, OBSERVABLE, TELEMETRY, NO_GUIDANCE = "covered", "observable_gap", "telemetry_gap", "no_guidance"


@dataclass
class TechniqueResult:
    attack_id: str
    name: str
    tactics: list[str]
    status: str
    rule_ids: list[str] = field(default_factory=list)
    matching_log_sources: list[str] = field(default_factory=list)   # ATT&CK names you can feed
    needed_log_sources: list[str] = field(default_factory=list)     # ATT&CK names, if telemetry gap
    data_components: list[str] = field(default_factory=list)
    covered_via_subtechniques: bool = False


@dataclass
class CoverageReport:
    attack_version: str
    rules_total: int
    rules_with_mitre: int
    unknown_technique_ids: dict[str, list[str]]       # technique id in a rule but not in ATT&CK -> rule ids
    results: dict[str, TechniqueResult]


def load_declared_sources(config_path: str | Path, mapping_path: str | Path) -> dict[str, list[str]]:
    """Return {declared_key: [attack log-source patterns]} for the collected sources only."""
    cfg = yaml.safe_load(Path(config_path).read_text(encoding="utf-8")) or {}
    mapping = yaml.safe_load(Path(mapping_path).read_text(encoding="utf-8")) or {}
    out: dict[str, list[str]] = {}
    for key in cfg.get("collected", []):
        if key not in mapping:
            raise KeyError(f"log source '{key}' has no entry in {mapping_path}")
        out[key] = mapping[key]
    return out


def _matches(attack_name: str, patterns: list[str]) -> bool:
    low = attack_name.lower()
    return any(fnmatchcase(low, p.lower()) for p in patterns)


def analyze(rules: list[WazuhRule], attack: AttackData, declared: dict[str, list[str]],
            min_level: int = 1) -> CoverageReport:
    """`min_level`: ignore rules below this level (level 0 rules never alert)."""
    by_tech: dict[str, list[str]] = {}
    unknown: dict[str, list[str]] = {}
    usable = [r for r in rules if r.level >= min_level and not r.noalert]
    for r in usable:
        for tid in r.mitre_ids:
            resolved_tid = attack.resolve_technique_id(tid)
            if resolved_tid in attack.techniques:
                by_tech.setdefault(resolved_tid, []).append(r.rule_id)
            else:
                unknown.setdefault(tid, []).append(r.rule_id)

    all_patterns = [p for pats in declared.values() for p in pats]
    results: dict[str, TechniqueResult] = {}
    for tid, t in attack.techniques.items():
        rule_ids = sorted(set(by_tech.get(tid, [])), key=lambda x: int(x) if x.isdigit() else 0)
        matching = sorted(n for n in t.log_sources if _matches(n, all_patterns))
        matching_components = sorted(c for c in t.data_components if _matches(c, all_patterns))
        matching = sorted(set(matching + matching_components))
        if rule_ids:
            status, needed = COVERED, []
        elif matching:
            status, needed = OBSERVABLE, []
        elif t.log_sources or t.data_components:
            status, needed = TELEMETRY, sorted(set(t.log_sources) | set(t.data_components))
        else:
            status, needed = NO_GUIDANCE, []
        results[tid] = TechniqueResult(
            tid, t.name, t.tactics, status, rule_ids, matching, needed,
            sorted(t.data_components),
        )

    # parent technique is "covered via sub-techniques" if only a sub-technique has a rule
    for tid, res in results.items():
        if attack.techniques[tid].is_subtechnique and res.status == COVERED:
            parent = results.get(attack.techniques[tid].parent_id or "")
            if parent is not None and parent.status != COVERED:
                parent.covered_via_subtechniques = True

    return CoverageReport(
        attack_version=attack.version,
        rules_total=len(rules),
        rules_with_mitre=sum(1 for r in rules if r.mitre_ids),
        unknown_technique_ids=unknown,
        results=results,
    )


def summarize(report: CoverageReport, attack: AttackData, only_parents: bool = False) -> dict[str, dict[str, int]]:
    """Counts per tactic and status."""
    out: dict[str, dict[str, int]] = {}
    for tid, res in report.results.items():
        if only_parents and attack.techniques[tid].is_subtechnique:
            continue
        for tac in res.tactics:
            out.setdefault(tac, {COVERED: 0, OBSERVABLE: 0, TELEMETRY: 0, NO_GUIDANCE: 0})[res.status] += 1
    return out


TACTIC_PRIORITY = ["initial-access", "credential-access", "execution", "persistence", "privilege-escalation",
                   "lateral-movement", "stealth", "defense-impairment", "command-and-control", "exfiltration",
                   "impact", "discovery", "collection"]


def _prio(r: "TechniqueResult") -> int:
    ranks = [TACTIC_PRIORITY.index(t) for t in r.tactics if t in TACTIC_PRIORITY]
    return min(ranks) if ranks else len(TACTIC_PRIORITY)


def top_candidate_gaps(report: CoverageReport, attack: AttackData, n: int = 10) -> list[TechniqueResult]:
    """Rank observable gaps by tactic priority, then by number of usable log sources."""
    gaps = [r for r in report.results.values() if r.status == OBSERVABLE]
    # simple, explainable ranking: tactic priority, then how many of your log sources can feed it
    gaps.sort(key=lambda r: (_prio(r), -len(r.matching_log_sources), attack.techniques[r.attack_id].is_subtechnique, r.attack_id))
    return gaps[:n]
