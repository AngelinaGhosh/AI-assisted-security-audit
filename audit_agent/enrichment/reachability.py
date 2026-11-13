"""Dependency reachability: is the vulnerable package actually used?

A vulnerable package that is never imported is much less urgent than one
the app calls on every request. Results, strongest evidence first:

  called       OSV-Scanner's call analysis saw the vulnerable function called (Go, Rust)
  not_called   OSV-Scanner's call analysis saw it is NOT called
  imported     the package is listed directly and imported in the code
  not_imported listed directly in a manifest but never imported (often a dev/build tool)
  transitive   not listed directly: pulled in by another dependency, so it may
               still run indirectly
  unknown      can't tell for this ecosystem
"""
from audit_agent.enrichment.codebase import CodebaseIndex, _top
from audit_agent.models_ext import DependencyFinding

# PyPI distribution name -> module you actually import, where they differ
PYPI_IMPORT_NAMES = {
    "pyyaml": ["yaml"], "beautifulsoup4": ["bs4"], "pillow": ["pil"], "scikit-learn": ["sklearn"],
    "python-dateutil": ["dateutil"], "opencv-python": ["cv2"], "opencv-python-headless": ["cv2"],
    "pyjwt": ["jwt"], "python-dotenv": ["dotenv"], "psycopg2-binary": ["psycopg2"],
    "protobuf": ["google"], "attrs": ["attr", "attrs"], "pycryptodome": ["crypto"],
    "pycryptodomex": ["cryptodome"], "setuptools": ["setuptools", "pkg_resources"],
    "msgpack-python": ["msgpack"], "python-multipart": ["multipart"], "pymongo": ["pymongo", "bson"],
    "mysqlclient": ["mysqldb"], "python-jose": ["jose"], "markupsafe": ["markupsafe"],
    "pywin32": ["win32api", "win32con"], "google-cloud-storage": ["google"],
}

_ECOSYSTEM_LANG = {
    "pypi": "python", "npm": "js", "go": "go", "crates.io": "rust", "maven": "java",
    "packagist": "php", "rubygems": "ruby", "nuget": "csharp",
}


def check_dependency(f: DependencyFinding, idx: CodebaseIndex) -> tuple[str, str]:
    """Return (state, human-readable reason)."""
    if f.called is True:
        return "called", "OSV call analysis: the vulnerable function is called"
    if f.called is False:
        return "not_called", "OSV call analysis: the vulnerable function is never called"

    lang = _ECOSYSTEM_LANG.get(f.ecosystem.lower())
    if not lang:
        return "unknown", f"can't check imports for {f.ecosystem or 'this'} ecosystem"

    imported = _is_imported(f.package, lang, idx)
    direct = _is_direct(f.package, f.ecosystem, idx)

    if imported:
        return "imported", f"{f.package} is imported by the code"
    if not direct:
        return "transitive", f"{f.package} isn't a direct dependency (pulled in by another package)"
    if lang in idx.imports:
        return "not_imported", f"{f.package} is listed as a dependency but never imported"
    return "unknown", f"no {lang} source files found to check imports"


def _is_imported(package: str, lang: str, idx: CodebaseIndex) -> bool:
    mods = idx.imports.get(lang, set())
    if not mods:
        return False
    name = package.lower()
    tops = {_top(m, lang) for m in mods}
    lowered = {m.lower() for m in mods}

    if lang == "python":
        candidates = set(PYPI_IMPORT_NAMES.get(name, [])) | {name.replace("-", "_"), name.replace("-", "")}
        return bool(candidates & tops)
    if lang == "js":
        return name in tops
    if lang == "go":
        return any(m == name or m.startswith(name + "/") for m in lowered)
    if lang == "rust":
        return name.replace("-", "_") in tops
    if lang == "java":
        group = name.split(":")[0]
        return any(m.startswith(group) for m in lowered)
    if lang == "php":
        vendor = name.split("/")[0].replace("-", "")
        return any(m.replace("-", "").startswith(vendor) for m in lowered)
    if lang == "ruby":
        return name in tops or name.replace("-", "/") in tops
    if lang == "csharp":
        return any(m.startswith(name) for m in lowered)
    return False


def _is_direct(package: str, ecosystem: str, idx: CodebaseIndex) -> bool:
    """Is the package named in one of the repo's own manifest files?"""
    text = idx.manifest_text
    if not text:
        return True   # no manifests to compare against (e.g. lockfile only): don't penalise
    name = package.lower()
    if ecosystem.lower() == "maven":
        name = name.split(":")[-1]       # artifactId appears in pom.xml
    variants = {name, name.replace("-", "_"), name.replace("_", "-")}
    return any(v in text for v in variants)
