import json

from soc_coverage.attack import AttackData, Technique, load_attack
from soc_coverage.cli import RULES_API, WAZUH_BRANCH
from soc_coverage.coverage import COVERED, OBSERVABLE, TELEMETRY, NO_GUIDANCE, analyze
from soc_coverage.recommend import deterministic, generate, recommend, validate
from soc_coverage.report import to_markdown
from soc_coverage.wazuh_parser import parse_rules_text

XML = """<?xml version="1.0"?>
<!-- comment -->
<group name="syslog,sshd,">
  <rule id="5712" level="10" frequency="8">
    <if_matched_sid>5710</if_matched_sid>
    <description>sshd: brute force</description>
    <mitre><id>T1110</id></mitre>
    <group>authentication_failures,</group>
  </rule>
  <rule id="5700" level="0" noalert="1"><description>grouped</description></rule>
</group>
<group name="web,"><rule id="31100" level="5"><description>web</description>
  <mitre><id>T9999</id></mitre></rule></group>
"""


def fake_attack():
    t = lambda i, ls, sub=False: Technique(i, "n" + i, ["credential-access"], sub, i.split(".")[0] if sub else None, [], set(ls))
    techs = {x.attack_id: x for x in [
        t("T1110", ["linux:syslog"]), t("T1110.001", ["linux:syslog"], True),
        t("T1003", ["WinEventLog:Sysmon"]), t("T1566", []), t("T1190", ["apache:access"])]}
    return AttackData("20.1", techs, {"credential-access": "Credential Access"})


def test_parser_extracts_mitre_and_ignores_noalert():
    rules = parse_rules_text(XML)
    r = {x.rule_id: x for x in rules}
    assert r["5712"].mitre_ids == ["T1110"] and r["5712"].level == 10
    assert "authentication_failures" in r["5712"].groups and "sshd" in r["5712"].groups
    assert r["5700"].noalert


def test_three_state_classification_and_unknown_ids():
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"], "web": ["apache:*"]})
    s = {k: v.status for k, v in rep.results.items()}
    assert s["T1110"] == COVERED
    assert s["T1110.001"] == OBSERVABLE      # no rule of its own, but linux:syslog can feed it
    assert s["T1190"] == OBSERVABLE          # wildcard match apache:*
    assert s["T1003"] == TELEMETRY           # Sysmon not collected -> telemetry gap, not a detection gap
    assert s["T1566"] == NO_GUIDANCE         # unknown is not reported as a gap
    assert "T9999" in rep.unknown_technique_ids


def test_llm_guardrail_rejects_undeclared_log_source():
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"]})
    res = rep.results["T1110.001"]
    good = '{"technique_id":"T1110.001","detection_idea":"Alert on 10 failed SSH logins in 2 minutes","required_log_sources":["linux:syslog"],"suggested_test":"hydra against a lab host"}'
    bad = good.replace("linux:syslog", "WinEventLog:Sysmon")
    assert validate(good, res).needs_human_review
    assert validate(bad, res) is None
    assert validate("not json", res) is None


def test_ollama_valid_response_is_accepted(monkeypatch):
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"]})
    res = rep.results["T1110.001"]
    valid = {
        "technique_id": "T1110.001",
        "detection_idea": "Alert on repeated failed SSH authentication patterns from the same source over a short interval.",
        "required_log_sources": ["linux:syslog"],
        "suggested_test": "Run a short SSH brute-force sequence in a lab and verify the alert fires.",
        "false_positive_notes": "Validate against legitimate user lockout activity.",
    }

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload.encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def read(self):
            return self._payload

    monkeypatch.setattr("soc_coverage.recommend.urllib.request.urlopen", lambda req, timeout=60: FakeResponse(json.dumps({"response": json.dumps(valid)})))
    rec = generate(fake_attack().techniques["T1110.001"], res, provider="ollama")
    assert rec is not None
    assert rec.technique_id == "T1110.001"
    assert rec.needs_human_review is True


def test_ollama_rejects_malformed_or_undeclared_responses(monkeypatch):
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"]})
    res = rep.results["T1110.001"]

    class FakeResponse:
        def __init__(self, payload):
            self._payload = payload.encode("utf-8")
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def read(self):
            return self._payload

    malformed = '{"technique_id": "T1110.001"}'
    undeclared = '{"technique_id": "T1110.001","detection_idea":"Monitor Windows events for failed password activity.","required_log_sources":["WinEventLog:Sysmon"],"suggested_test":"Observe a Windows login burst."}'
    monkeypatch.setattr("soc_coverage.recommend.urllib.request.urlopen", lambda req, timeout=60: FakeResponse(json.dumps({"response": malformed})))
    assert generate(fake_attack().techniques["T1110.001"], res, provider="ollama") is None
    monkeypatch.setattr("soc_coverage.recommend.urllib.request.urlopen", lambda req, timeout=60: FakeResponse(json.dumps({"response": undeclared})))
    assert generate(fake_attack().techniques["T1110.001"], res, provider="ollama") is None


def test_ollama_retry_and_fallback_are_deterministic(monkeypatch):
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"]})
    res = rep.results["T1110.001"]
    payload = {
        "technique_id": "T1110.001",
        "detection_idea": "Alert on repeated failed SSH authentication attempts across a short time window.",
        "required_log_sources": ["linux:syslog"],
        "suggested_test": "Run a controlled SSH brute-force sequence against a lab host and confirm the alert fires.",
        "false_positive_notes": "Validate against benign password mistakes.",
    }
    calls = {"count": 0}

    def fake_generate(prompt):
        calls["count"] += 1
        if calls["count"] == 1:
            raise ValueError("temporary failure")
        return json.dumps(payload)

    monkeypatch.setattr("soc_coverage.recommend._ollama_generate", fake_generate)
    rec = generate(fake_attack().techniques["T1110.001"], res, retries=1, provider="ollama")
    assert rec is not None and rec.needs_human_review
    assert calls["count"] == 2

    monkeypatch.setattr("soc_coverage.recommend.generate", lambda *args, **kwargs: None)
    rec = recommend(fake_attack().techniques["T1110.001"], res, provider="ollama")
    assert rec.needs_human_review
    assert rec.required_log_sources == ["linux:syslog"]


def test_deterministic_recommendation_is_always_reviewable():
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"]})
    res = rep.results["T1110.001"]
    rec = deterministic(fake_attack().techniques["T1110.001"], res)
    assert rec.needs_human_review
    assert rec.required_log_sources == ["linux:syslog"]


def test_data_components_can_make_a_technique_observable():
    attack = fake_attack()
    attack.techniques["T1003"].data_components.add("WinEventLog:Security")
    rep = analyze(parse_rules_text(XML), attack, {"windows": ["WinEventLog:*"]})
    assert rep.results["T1003"].status == OBSERVABLE
    assert rep.results["T1003"].data_components == ["WinEventLog:Security"]


def test_revoked_attack_ids_are_remapped_before_classification():
    attack = fake_attack()
    attack.technique_id_aliases["T1059"] = "T1110"
    rules = parse_rules_text(
        '<group name="test"><rule id="1" level="5"><mitre><id>T1059</id></mitre></rule></group>'
    )
    rep = analyze(rules, attack, {})
    assert rep.results["T1110"].status == COVERED
    assert "T1059" not in rep.unknown_technique_ids


def test_unknown_diagnostic_filters_tactic_and_placeholder_ids():
    rep = analyze(parse_rules_text(XML), fake_attack(), {"linux": ["linux:syslog"]})
    rep.unknown_technique_ids = {
        "TA0001": ["1001", "1002"],
        "$(THREAT.SOFTWARE.ID)": ["9999"],
        "T9999": ["2001"],
    }
    md = to_markdown(rep, fake_attack(), {"linux": ["linux:syslog"]})
    assert "TA0001" not in md
    assert "$(THREAT.SOFTWARE.ID)" not in md
    assert "T9999" in md


def test_wazuh_fetch_is_pinned_to_master():
    assert WAZUH_BRANCH == "master"
    assert "ref=master" in RULES_API


def test_loader_follows_revoked_by_replacement_chain(tmp_path):
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "x-mitre-collection", "id": "collection", "x_mitre_version": "20.1"},
            {
                "type": "attack-pattern", "id": "old", "name": "Old",
                "revoked": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9000"}],
            },
            {
                "type": "attack-pattern", "id": "middle", "name": "Middle",
                "x_mitre_deprecated": True,
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9001"}],
            },
            {
                "type": "attack-pattern", "id": "current", "name": "Current",
                "external_references": [{"source_name": "mitre-attack", "external_id": "T9002"}],
            },
            {"type": "relationship", "id": "rel-old-middle", "relationship_type": "revoked-by",
             "source_ref": "old", "target_ref": "middle"},
            {"type": "relationship", "id": "rel-middle-current", "relationship_type": "revoked-by",
             "source_ref": "middle", "target_ref": "current"},
        ],
    }
    path = tmp_path / "attack.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    attack = load_attack(path)
    assert attack.resolve_technique_id("T9000") == "T9002"
    assert attack.resolve_technique_id("T9001") == "T9002"
    assert set(attack.techniques) == {"T9002"}
