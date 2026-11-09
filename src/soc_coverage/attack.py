"""Load MITRE ATT&CK Enterprise STIX data (ATT&CK v18+ detection model).

Model used:  technique <-(detects)- detection strategy -> analytics -> log source references.
Each log source reference carries a name such as "WinEventLog:Security" or "linux:syslog";
that is what we match against the log sources the SOC declares it collects.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Technique:
    attack_id: str                      # e.g. T1110 or T1110.001
    name: str
    tactics: list[str]                  # kill-chain phase names, e.g. credential-access
    is_subtechnique: bool
    parent_id: str | None
    platforms: list[str] = field(default_factory=list)
    log_sources: set[str] = field(default_factory=set)   # ATT&CK log source names (from analytics)
    data_components: set[str] = field(default_factory=set)
    detection_strategies: list[str] = field(default_factory=list)
    description: str = ""


@dataclass
class AttackData:
    version: str
    techniques: dict[str, Technique]
    tactics: dict[str, str]             # shortname -> display name
    technique_id_aliases: dict[str, str] = field(default_factory=dict)

    def resolve_technique_id(self, attack_id: str) -> str:
        """Resolve revoked/deprecated ATT&CK IDs to their active replacement."""
        current = attack_id
        seen: set[str] = set()
        while current in self.technique_id_aliases and current not in seen:
            seen.add(current)
            replacement = self.technique_id_aliases[current]
            if replacement == current:
                break
            current = replacement
        return current


def _attack_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_attack(path: str | Path) -> AttackData:
    bundle = json.loads(Path(path).read_text(encoding="utf-8"))
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs if "id" in o}

    def active(o: dict) -> bool:
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    version = next((o.get("x_mitre_version", "?") for o in objs if o["type"] == "x-mitre-collection"), "?")
    tactics = {
        o["x_mitre_shortname"]: o["name"]
        for o in objs
        if o["type"] == "x-mitre-tactic" and active(o)
    }

    techniques: dict[str, Technique] = {}
    stix_to_attack: dict[str, str] = {}
    all_stix_to_attack: dict[str, str] = {}
    data_components_by_id = {
        o["id"]: o.get("name", "")
        for o in objs
        if "id" in o and o.get("type") == "x-mitre-data-component" and active(o)
    }

    for o in objs:
        if o["type"] != "attack-pattern":
            continue
        aid = _attack_id(o)
        if not aid:
            continue
        all_stix_to_attack[o["id"]] = aid
        if not active(o):
            continue
        stix_to_attack[o["id"]] = aid
        techniques[aid] = Technique(
            attack_id=aid,
            name=o["name"],
            tactics=[p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"],
            is_subtechnique=bool(o.get("x_mitre_is_subtechnique")),
            parent_id=aid.split(".")[0] if o.get("x_mitre_is_subtechnique") else None,
            platforms=o.get("x_mitre_platforms", []),
            data_components=set(o.get("x_mitre_data_sources", [])),
            description=(o.get("description") or "").strip(),
        )

    for rel in objs:
        if rel["type"] != "relationship" or rel["relationship_type"] != "detects":
            continue
        strat = by_id.get(rel["source_ref"])
        tech_id = stix_to_attack.get(rel["target_ref"])
        if not strat or strat["type"] != "x-mitre-detection-strategy" or not active(strat) or not tech_id:
            continue
        tech = techniques[tech_id]
        tech.detection_strategies.append(strat["name"])
        for aref in strat.get("x_mitre_analytic_refs", []):
            analytic = by_id.get(aref)
            if not analytic:
                continue
            for ls in analytic.get("x_mitre_log_source_references", []):
                name = (ls.get("name") or "").strip()
                if name:
                    tech.log_sources.add(name)

    # Follow ATT&CK's revoked-by graph before coverage classification. A
    # replacement may itself be revoked, so resolve chains after collecting
    # every relationship rather than assuming a single hop.
    revoked_by: dict[str, str] = {}
    for rel in objs:
        if rel.get("type") == "relationship" and rel.get("relationship_type") == "revoked-by":
            source = rel.get("source_ref")
            target = rel.get("target_ref")
            if source in all_stix_to_attack and target in all_stix_to_attack:
                revoked_by[all_stix_to_attack[source]] = all_stix_to_attack[target]

    aliases: dict[str, str] = {}
    for old_id in all_stix_to_attack.values():
        current = old_id
        seen: set[str] = set()
        while current in revoked_by and current not in seen:
            seen.add(current)
            current = revoked_by[current]
        if old_id != current and current in techniques:
            aliases[old_id] = current

    # Newer ATT&CK bundles model data components as STIX relationships. Support
    # both the current relationship shape and the legacy attack-pattern field.
    for rel in objs:
        if rel.get("type") != "relationship" or rel.get("relationship_type") not in {"uses", "detects"}:
            continue
        tech_id = stix_to_attack.get(rel.get("source_ref")) or stix_to_attack.get(rel.get("target_ref"))
        component_id = rel.get("target_ref") if rel.get("target_ref") in data_components_by_id else rel.get("source_ref")
        if tech_id and component_id in data_components_by_id:
            techniques[tech_id].data_components.add(data_components_by_id[component_id])

    return AttackData(version=version, techniques=techniques, tactics=tactics, technique_id_aliases=aliases)
