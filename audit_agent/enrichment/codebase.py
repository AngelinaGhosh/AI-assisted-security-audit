"""One pass over the target repo, shared by the reachability and exposure
checks: which packages the code imports, which manifests list which
packages directly, and whether it looks like an internet-facing service.

These are fast text heuristics, not a full call graph. They are meant to
push obviously-unused or internal-only issues down the list, not to prove
anything is safe.
"""
import re
from dataclasses import dataclass, field
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__", "site-packages",
    "vendor", "dist", "build", "target", ".tox", ".mypy_cache", ".next", ".gradle",
}
MAX_FILES = 5000
MAX_FILE_BYTES = 1_000_000

LANG = {
    ".py": "python",
    ".js": "js", ".jsx": "js", ".ts": "js", ".tsx": "js", ".mjs": "js", ".cjs": "js",
    ".go": "go", ".rs": "rust", ".java": "java", ".kt": "java", ".scala": "java",
    ".php": "php", ".rb": "ruby", ".cs": "csharp",
}
MANIFESTS = {
    "requirements.txt", "requirements-dev.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg",
    "package.json", "go.mod", "Cargo.toml", "pom.xml", "build.gradle", "build.gradle.kts",
    "composer.json", "Gemfile",
}

_IMPORT_RE = {
    "python": [re.compile(r"^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)", re.M),
               re.compile(r"^\s*from\s+([\w.]+)\s+import\b", re.M)],
    "js": [re.compile(r"""require\(\s*['"]([^'"]+)['"]\s*\)"""),
           re.compile(r"""\bfrom\s+['"]([^'"]+)['"]"""),
           re.compile(r"""^\s*import\s+['"]([^'"]+)['"]""", re.M),
           re.compile(r"""import\(\s*['"]([^'"]+)['"]\s*\)""")],
    "go": [re.compile(r'^\s*import\s+(?:\w+\s+)?"([^"]+)"', re.M),
           re.compile(r'^\s+(?:[\w.]+\s+)?"([^"]+)"\s*$', re.M)],
    "rust": [re.compile(r"^\s*(?:pub\s+)?use\s+(\w+)::", re.M),
             re.compile(r"^\s*extern\s+crate\s+(\w+)", re.M)],
    "java": [re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)", re.M)],
    "php": [re.compile(r"^\s*use\s+([\w\\]+)", re.M)],
    "ruby": [re.compile(r"""^\s*require\s+['"]([^'"]+)['"]""", re.M)],
    "csharp": [re.compile(r"^\s*using\s+([\w.]+)\s*;", re.M)],
}

# web frameworks / servers -> the code serves requests from the network
_WEB_MARKERS = {
    "python": {"flask", "fastapi", "django", "starlette", "tornado", "aiohttp", "bottle", "sanic", "falcon", "pyramid", "quart"},
    "js": {"express", "koa", "fastify", "@hapi/hapi", "hapi", "next", "@nestjs/core", "restify", "http", "https", "node:http"},
    "go": {"net/http", "github.com/gin-gonic/gin", "github.com/labstack/echo", "github.com/gofiber/fiber", "github.com/gorilla/mux"},
    "rust": {"actix_web", "axum", "rocket", "warp", "hyper"},
    "java": {"org.springframework.web", "javax.servlet", "jakarta.servlet", "io.javalin", "io.micronaut"},
    "php": {"illuminate", "symfony"},
    "ruby": {"sinatra", "rails", "rack"},
    "csharp": {"microsoft.aspnetcore"},
}


@dataclass
class CodebaseIndex:
    root: Path
    imports: dict[str, set[str]] = field(default_factory=dict)    # lang -> imported module names
    sources: dict[str, str] = field(default_factory=dict)         # path -> text (source files only)
    manifest_text: str = ""                                       # all manifests, lower-cased
    web_frameworks: set[str] = field(default_factory=set)
    exposure_signals: list[str] = field(default_factory=list)

    @property
    def is_web_service(self) -> bool:
        return bool(self.web_frameworks)


def build_index(root: str | Path) -> CodebaseIndex:
    root = Path(root).resolve()
    idx = CodebaseIndex(root=root)
    manifests: list[str] = []
    count = 0

    for path in root.rglob("*"):
        if count >= MAX_FILES:
            break
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts[:-1]):
            continue
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
        except OSError:
            continue

        name = path.name
        if name in MANIFESTS or name.endswith(".csproj"):
            manifests.append(_read(path))
        if name == "Dockerfile" or name.startswith("Dockerfile."):
            text = _read(path)
            ports = re.findall(r"^\s*EXPOSE\s+(.+)$", text, re.M)
            if ports:
                idx.exposure_signals.append(f"Dockerfile exposes port {', '.join(p.strip() for p in ports)}")

        lang = LANG.get(path.suffix.lower())
        if not lang:
            continue
        count += 1
        text = _read(path)
        idx.sources[str(path)] = text
        mods = idx.imports.setdefault(lang, set())
        for rx in _IMPORT_RE[lang]:
            for m in rx.findall(text):
                for mod in m.split(","):
                    mod = mod.strip().split(" as ")[0].strip()
                    if mod:
                        mods.add(mod)

    idx.manifest_text = "\n".join(manifests).lower()

    for lang, mods in idx.imports.items():
        tops = {_top(m, lang) for m in mods} | {m.lower() for m in mods}
        for marker in _WEB_MARKERS.get(lang, ()):
            if marker in tops or any(m.lower().startswith(marker) for m in mods):
                idx.web_frameworks.add(marker)
    if any(re.search(r"""host\s*=\s*['"]0\.0\.0\.0['"]|['"]0\.0\.0\.0['"]""", t) for t in idx.sources.values()):
        idx.exposure_signals.append("server binds to 0.0.0.0 (all network interfaces)")
    return idx


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _top(module: str, lang: str) -> str:
    """Top-level package name for an import."""
    m = module.lower()
    if lang == "python":
        return m.split(".")[0]
    if lang == "js":
        if m.startswith("node:"):
            return m
        parts = m.split("/")
        return "/".join(parts[:2]) if m.startswith("@") else parts[0]
    if lang == "php":
        return m.split("\\")[0]
    if lang == "csharp":
        return m
    return m
