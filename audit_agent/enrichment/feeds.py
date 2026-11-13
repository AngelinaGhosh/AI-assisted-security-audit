"""Threat-intel feeds: CISA KEV and FIRST EPSS.

- CISA KEV (Known Exploited Vulnerabilities): CVEs that CISA has
  confirmed are being exploited in the wild. If a CVE is in KEV, it's a
  real, current attack, not a theoretical one.
  https://www.cisa.gov/known-exploited-vulnerabilities-catalog

- EPSS (Exploit Prediction Scoring System, by FIRST): the probability
  (0-1) that a CVE gets exploited in the next 30 days, updated daily.
  https://www.first.org/epss/

Both are free and need no API key. Responses are cached on disk for a day
(~/.cache/threatflow, or THREATFLOW_CACHE) so repeated scans are fast and
work offline. If a feed can't be reached, the stale cache is used if
there is one; otherwise that signal is just marked unknown and the scan
carries on.
"""
import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
CACHE_TTL = 24 * 3600
EPSS_BATCH = 100        # CVEs per request; keeps the URL well under length limits
TIMEOUT = 20


def cache_dir() -> Path:
    d = Path(os.environ.get("THREATFLOW_CACHE") or Path.home() / ".cache" / "threatflow")
    d.mkdir(parents=True, exist_ok=True)
    return d


def _get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ThreatFlow-security-audit/2.0", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ------------------------------------------------------------------ KEV

def load_kev(offline: bool = False) -> tuple[dict[str, dict] | None, str]:
    """Return ({CVE-ID: kev_entry}, status_note). The dict is None if KEV
    data isn't available at all."""
    path = cache_dir() / "kev.json"
    fresh = path.exists() and time.time() - path.stat().st_mtime < CACHE_TTL

    data = None
    note = ""
    if fresh or offline:
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            note = "KEV: cached copy" if fresh else "KEV: offline, using stale cached copy"
    if data is None and not offline:
        try:
            data = _get_json(KEV_URL)
            path.write_text(json.dumps(data), encoding="utf-8")
            note = "KEV: downloaded latest catalog"
        except Exception as e:  # network down, blocked, bad JSON...
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                note = f"KEV: couldn't download ({type(e).__name__}), using stale cache"
            else:
                return None, f"KEV: unavailable ({type(e).__name__}), skipped"
    if data is None:
        return None, "KEV: offline and no cached copy, skipped"

    catalog = {v["cveID"].upper(): v for v in data.get("vulnerabilities", []) if v.get("cveID")}
    return catalog, f"{note} ({len(catalog)} CVEs, version {data.get('catalogVersion', '?')})"


# ----------------------------------------------------------------- EPSS

def load_epss(cves: list[str], offline: bool = False) -> tuple[dict[str, dict] | None, str]:
    """Return ({CVE-ID: {"epss": float, "percentile": float}}, status_note)."""
    cves = sorted({c.upper() for c in cves if c.upper().startswith("CVE-")})
    if not cves:
        return {}, "EPSS: no CVEs to look up"

    path = cache_dir() / "epss.json"
    try:
        cache: dict = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    except (OSError, json.JSONDecodeError):
        cache = {}

    now = time.time()
    need = [c for c in cves if c not in cache or now - cache[c].get("fetched", 0) > CACHE_TTL]
    error = None
    if need and not offline:
        for i in range(0, len(need), EPSS_BATCH):
            chunk = need[i:i + EPSS_BATCH]
            url = EPSS_URL + "?" + urllib.parse.urlencode({"cve": ",".join(chunk)})
            try:
                rows = _get_json(url).get("data", [])
            except Exception as e:
                error = type(e).__name__
                break
            returned = set()
            for row in rows:
                cve = row.get("cve", "").upper()
                returned.add(cve)
                cache[cve] = {
                    "epss": float(row.get("epss", 0)),
                    "percentile": float(row.get("percentile", 0)),
                    "fetched": now,
                }
            for cve in set(chunk) - returned:      # EPSS has no score yet (very new CVE)
                cache[cve] = {"epss": None, "percentile": None, "fetched": now}
        try:
            path.write_text(json.dumps(cache), encoding="utf-8")
        except OSError:
            pass

    found = {c: cache[c] for c in cves if c in cache and cache[c].get("epss") is not None}
    if error and not found:
        return None, f"EPSS: unavailable ({error}), skipped"
    if offline and not found:
        return None, "EPSS: offline and nothing cached, skipped"
    note = f"EPSS: scores for {len(found)} of {len(cves)} CVEs"
    if error:
        note += f" (some lookups failed: {error})"
    return found, note
