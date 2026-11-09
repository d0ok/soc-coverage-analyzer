"""Parse Wazuh rule XML files and extract the MITRE ATT&CK technique IDs they declare.

Wazuh rule files have several top-level <group> elements and no single root, so each
file is wrapped in a synthetic <root> before parsing.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path

_XML_DECL = re.compile(r"^\s*<\?xml[^>]*\?>", re.IGNORECASE)


@dataclass
class WazuhRule:
    rule_id: str
    level: int
    description: str
    source_file: str
    mitre_ids: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    if_sid: list[str] = field(default_factory=list)
    noalert: bool = False


def _split_csv(text: str | None) -> list[str]:
    return [p.strip() for p in (text or "").split(",") if p.strip()]


def parse_rules_text(xml_text: str, source_file: str = "<memory>") -> list[WazuhRule]:
    body = _XML_DECL.sub("", xml_text)
    body = re.sub(r"(?<=\\)<(?!/)", "&lt;", body)  # escape < after a backslash (regex text, not a tag)
    root = ET.fromstring(f"<root>{body}</root>")
    rules: list[WazuhRule] = []
    for group in root.iter("group"):
        # only <group name="..."> wrappers, not <group> tags nested inside a <rule>
        if group.get("name") is None:
            continue
        group_names = _split_csv(group.get("name"))
        for rule in group.findall("rule"):
            rule_groups = list(group_names)
            for g in rule.findall("group"):
                rule_groups += _split_csv(g.text)
            mitre = [
                (i.text or "").strip().upper()
                for m in rule.findall("mitre")
                for i in m.findall("id")
                if (i.text or "").strip()
            ]
            rules.append(
                WazuhRule(
                    rule_id=rule.get("id", ""),
                    level=int(rule.get("level", "0")),
                    description=(rule.findtext("description") or "").strip(),
                    source_file=source_file,
                    mitre_ids=mitre,
                    groups=rule_groups,
                    if_sid=_split_csv(rule.findtext("if_sid")),
                    noalert=rule.get("noalert") == "1",
                )
            )
    return rules


def parse_rules_dir(path: str | Path) -> list[WazuhRule]:
    """Parse every *.xml file in a directory (non-recursive, sorted)."""
    rules: list[WazuhRule] = []
    for f in sorted(Path(path).glob("*.xml")):
        try:
            rules += parse_rules_text(f.read_text(encoding="utf-8", errors="replace"), f.name)
        except ET.ParseError as exc:  # keep going, but never fail silently
            print(f"[warn] could not parse {f.name}: {exc}")
    return rules
