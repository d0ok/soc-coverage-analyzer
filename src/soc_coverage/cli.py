from __future__ import annotations

import argparse
import json
import os
import urllib.request
from dataclasses import asdict
from pathlib import Path

from .attack import load_attack
from .coverage import analyze, load_declared_sources, top_candidate_gaps
from .navigator import to_layer
from .recommend import recommend
from .report import to_html, to_markdown
from .wazuh_parser import parse_rules_dir

ATTACK_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
WAZUH_BRANCH = "master"
RULES_API = f"https://api.github.com/repos/wazuh/wazuh/contents/ruleset/rules?ref={WAZUH_BRANCH}"


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "soc-coverage-analyzer"})
    with urllib.request.urlopen(req, timeout=120) as response:
        return response.read()


def _fetch_rules_api(rules_dir: Path) -> None:
    headers = {"User-Agent": "soc-coverage-analyzer"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(RULES_API, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as response:
        listing = json.loads(response.read())
    for item in listing:
        if item["name"].endswith(".xml"):
            (rules_dir / item["name"]).write_bytes(_get(item["download_url"]))


def _fetch_rules_git(rules_dir: Path) -> None:
    import shutil
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", "--depth", "1", "--filter=blob:none", "--sparse",
                        "--branch", WAZUH_BRANCH,
                        "https://github.com/wazuh/wazuh.git", tmp], check=True)
        subprocess.run(["git", "-C", tmp, "sparse-checkout", "set", "ruleset/rules"], check=True)
        for f in Path(tmp, "ruleset", "rules").glob("*.xml"):
            shutil.copy(f, rules_dir / f.name)


def fetch(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / "enterprise-attack.json").write_bytes(_get(ATTACK_URL))
    rules_dir = data_dir / "wazuh_rules"
    rules_dir.mkdir(exist_ok=True)
    try:
        _fetch_rules_api(rules_dir)
    except Exception as exc:
        print(f"[info] GitHub API failed ({exc}); trying git sparse clone")
        _fetch_rules_git(rules_dir)
    print(f"Data downloaded to {data_dir} ({len(list(rules_dir.glob('*.xml')))} rule files)")


def run(args: argparse.Namespace) -> None:
    attack = load_attack(args.attack)
    rules = parse_rules_dir(args.rules)
    declared = load_declared_sources(args.config, args.mapping)
    report = analyze(rules, attack, declared, min_level=args.min_level)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "coverage.json").write_text(json.dumps(
        {"attack_version": report.attack_version, "results": {k: asdict(v) for k, v in report.results.items()}},
        indent=2), encoding="utf-8")
    (out / "navigator_layer.json").write_text(json.dumps(to_layer(report, attack), indent=2), encoding="utf-8")
    (out / "report.md").write_text(to_markdown(report, attack, declared), encoding="utf-8")
    (out / "report.html").write_text(to_html(report, attack, declared), encoding="utf-8")
    recommendations = [
        recommend(attack.techniques[g.attack_id], g, use_ai=not args.no_ai).model_dump()
        for g in top_candidate_gaps(report, attack, args.max_recommendations)
    ]
    (out / "recommendations.json").write_text(json.dumps(recommendations, indent=2), encoding="utf-8")
    print(f"{report.rules_total} rules ({report.rules_with_mitre} with MITRE) -> results in {out}/")


def main() -> None:
    parser = argparse.ArgumentParser(prog="soc-coverage")
    sub = parser.add_subparsers(dest="cmd", required=True)
    fetch_parser = sub.add_parser("fetch", help="download ATT&CK STIX data and the Wazuh ruleset")
    fetch_parser.add_argument("--data-dir", default="data")
    analyze_parser = sub.add_parser("analyze", help="compute coverage and gaps")
    analyze_parser.add_argument("--rules", default="data/wazuh_rules")
    analyze_parser.add_argument("--attack", default="data/enterprise-attack.json")
    analyze_parser.add_argument("--config", default="config/log_sources.example.yaml")
    analyze_parser.add_argument("--mapping", default="config/logsource_mapping.yaml")
    analyze_parser.add_argument("--min-level", type=int, default=1)
    analyze_parser.add_argument("--out", default="output")
    analyze_parser.add_argument("--no-ai", action="store_true", help="force deterministic offline recommendations")
    analyze_parser.add_argument("--max-recommendations", type=int, default=5)
    args = parser.parse_args()
    fetch(Path(args.data_dir)) if args.cmd == "fetch" else run(args)


if __name__ == "__main__":
    main()
