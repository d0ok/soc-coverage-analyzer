"""Translate ATT&CK technique IDs that were retired (revoked) into their current replacements."""
import json
from pathlib import Path


def load_id_remap(path):
    objs = json.loads(Path(path).read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objs}

    def aid(o):
        for r in o.get("external_references", []):
            if r.get("source_name") == "mitre-attack":
                return r.get("external_id")

    nxt = {r["source_ref"]: r["target_ref"] for r in objs
           if r["type"] == "relationship" and r["relationship_type"] == "revoked-by"}
    remap = {}
    for o in objs:
        if o["type"] != "attack-pattern" or not o.get("revoked"):
            continue
        old, cur, seen = aid(o), o, set()
        while cur and cur.get("revoked") and cur["id"] in nxt and cur["id"] not in seen:
            seen.add(cur["id"])
            cur = by_id.get(nxt[cur["id"]])
        new = aid(cur) if cur else None
        if old and new and new != old:
            remap[old] = new
    return remap
