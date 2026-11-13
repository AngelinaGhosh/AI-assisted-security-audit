"""Risk enrichment. KEV and EPSS come from a temporary on-disk cache, so
nothing touches the network."""
import json
import os
import time

import pytest

from audit_agent.enrichment import enrich_findings, feeds
from audit_agent.enrichment.codebase import build_index
from audit_agent.enrichment.reachability import check_dependency
from audit_agent.enrichment.risk import priority_for
from audit_agent.models import Finding
from audit_agent.models_ext import DependencyFinding

DEMO = os.path.join(os.path.dirname(__file__), "..", "demo", "target")


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFLOW_CACHE", str(tmp_path))
    (tmp_path / "kev.json").write_text(json.dumps({"catalogVersion": "test", "vulnerabilities": [
        {"cveID": "CVE-2020-1747", "dateAdded": "2024-01-01", "knownRansomwareCampaignUse": "Known"}]}))
    (tmp_path / "epss.json").write_text(json.dumps({
        "CVE-2018-18074": {"epss": 0.62, "percentile": 0.98, "fetched": time.time()},
        "CVE-2023-30861": {"epss": 0.002, "percentile": 0.3, "fetched": time.time()}}))
    return tmp_path


def dep(package, cve, cvss, ecosystem="PyPI"):
    return DependencyFinding("dependency", cve, "requirements.txt", 0, package, "HIGH",
                             package=package, version="1", ecosystem=ecosystem, vuln_ids=[cve], cvss_score=cvss)


def code(line, rule="rule", sev="ERROR"):
    return Finding("semgrep", rule, os.path.join(DEMO, "app.py"), line, "msg", sev)


def test_feeds_read_from_cache_offline(cache):
    kev, note = feeds.load_kev(offline=True)
    assert "CVE-2020-1747" in kev
    epss, _ = feeds.load_epss(["CVE-2018-18074", "cve-2023-30861"], offline=True)
    assert epss["CVE-2018-18074"]["epss"] == 0.62 and "CVE-2023-30861" in epss


def test_feeds_degrade_gracefully_when_unavailable(tmp_path, monkeypatch):
    monkeypatch.setenv("THREATFLOW_CACHE", str(tmp_path))
    def boom(url):
        raise OSError("no network")
    monkeypatch.setattr(feeds, "_get_json", boom)
    kev, note = feeds.load_kev()
    assert kev is None and "unavailable" in note
    epss, note = feeds.load_epss(["CVE-2018-18074"])
    assert epss is None and "unavailable" in note


def test_dependency_reachability_on_demo():
    idx = build_index(DEMO)
    assert check_dependency(dep("flask", "CVE-1", 7.5), idx)[0] == "imported"
    assert check_dependency(dep("requests", "CVE-2", 7.5), idx)[0] == "not_imported"
    assert check_dependency(dep("werkzeug", "CVE-3", 7.5), idx)[0] == "transitive"
    assert check_dependency(dep("PyYAML", "CVE-4", 7.5), idx)[0] == "not_imported"   # imported as `yaml`, but isn't
    assert check_dependency(dep("x", "CVE-5", 7.5, ecosystem="Hex"), idx)[0] == "unknown"


def test_code_exposure_on_demo(cache):
    fs = [code(37), code(23), code(62, "flask-debug-enabled", "WARNING")]
    r = enrich_findings(fs, DEMO, offline=True)
    pickle, sqli, debug = (r.for_finding(f) for f in fs)
    assert (pickle.reachability, pickle.exposure) == ("reachable", "internet")    # inside @app.route
    assert sqli.reachability == "not_called"                                      # get_user() never called
    assert debug.exposure == "internet"                                           # app.run(host="0.0.0.0")
    assert pickle.priority == "P1" and pickle.score > sqli.score


def test_kev_and_epss_raise_priority(cache):
    kev_dep = dep("PyYAML", "CVE-2020-1747", 9.8)       # in KEV (ransomware), never imported
    epss_dep = dep("requests", "CVE-2018-18074", 7.5)   # EPSS 62%
    quiet_dep = dep("flask", "CVE-2023-30861", 7.5)     # imported, low EPSS
    control = dep("requests", "CVE-2099-0001", 7.5)     # same package, no KEV/EPSS data
    r = enrich_findings([kev_dep, epss_dep, quiet_dep, control], DEMO, offline=True)
    k, e, q, c = (r.for_finding(f) for f in (kev_dep, epss_dep, quiet_dep, control))
    assert k.in_kev is True and k.kev_ransomware is True and k.score >= 70
    assert any("KEV" in reason for reason in k.reasons)
    assert e.epss == 0.62 and e.score > c.score
    assert q.in_kev is False
    assert any(n.startswith("KEV") for n in r.notes)


def test_priority_bands():
    assert [priority_for(s) for s in (95, 80, 79, 60, 35, 34)] == ["P1", "P1", "P2", "P2", "P3", "P4"]


def test_llm_context_is_compact(cache):
    f = dep("requests", "CVE-2018-18074", 7.5)
    ctx = enrich_findings([f], DEMO, offline=True).llm_context()[id(f)]
    assert set(ctx) >= {"score", "priority", "reachability", "exposure", "cvss", "epss"}
    assert "reasons" not in ctx
