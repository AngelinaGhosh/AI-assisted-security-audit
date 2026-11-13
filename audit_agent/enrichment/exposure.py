"""Internet exposure and code reachability for code/secret findings.

For code findings, the question is: can a request from the internet get
to this line? Heuristics used (Python and JS/TS get the most support):

- the line is inside a route handler (Flask/FastAPI/Django/Express style)
  -> reachable from the internet
- the enclosing function is called from a route handler (one level deep)
  -> reachable from the internet
- the enclosing function is never referenced anywhere in the repo
  -> probably dead code (not_called)
- otherwise, if the repo is a web service -> internal code in an
  internet-facing app; if not a web service -> internal

Dependency findings are 'internet' exposed when the repo is a web service.
"""
import re
from pathlib import Path

from audit_agent.enrichment.codebase import CodebaseIndex
from audit_agent.models import Finding

_PY_DEF = re.compile(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(([^)]*)")
_PY_ROUTE_DECORATOR = re.compile(
    r"^\s*@[\w.]*\b(route|get|post|put|delete|patch|head|options|websocket|api_route|api_view|action)\s*\(",
    re.I,
)
_SECRET_RULE = re.compile(r"secret|api[-_]?key|password|token|credential|private[-_]?key", re.I)
_JS_ROUTE = re.compile(r"\b(app|router|server|api|fastify)\.(get|post|put|delete|patch|all|use|route)\s*\(")


def _function_at(lines: list[str], line_no: int) -> tuple[int, str, str] | None:
    """(def line index, function name, params) enclosing 1-based line_no, or None if module level."""
    if not 1 <= line_no <= len(lines):
        return None
    m = _PY_DEF.match(lines[line_no - 1])
    if m:
        return line_no - 1, m.group(2), m.group(3)
    target = lines[line_no - 1]
    threshold = len(target) - len(target.lstrip())
    # walk up through enclosing blocks (if/for/with/...) until we hit a def
    # or reach module level
    for i in range(line_no - 2, -1, -1):
        text = lines[i]
        if not text.strip() or text.lstrip().startswith(("#", "@")):
            continue
        indent = len(text) - len(text.lstrip())
        if indent < threshold:
            m = _PY_DEF.match(text)
            if m:
                return i, m.group(2), m.group(3)
            if indent == 0:
                return None
            threshold = indent
    return None


def _is_py_handler(lines: list[str], def_idx: int, params: str, path: str) -> bool:
    j = def_idx - 1
    while j >= 0 and lines[j].strip().startswith("@"):
        if _PY_ROUTE_DECORATOR.match(lines[j]):
            return True
        j -= 1
    # Django-style view: lives in views.py and takes `request` first
    return Path(path).name == "views.py" and params.strip().startswith("request")


def _python_handlers(idx: CodebaseIndex) -> dict[str, str]:
    """name -> body text of every route handler in the repo (cached on the index)."""
    cached = getattr(idx, "_handlers", None)
    if cached is not None:
        return cached
    handlers: dict[str, str] = {}
    for path, text in idx.sources.items():
        if not path.endswith(".py"):
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines):
            m = _PY_DEF.match(line)
            if m and _is_py_handler(lines, i, m.group(3), path):
                body = [line]
                base = len(m.group(1))
                for nxt in lines[i + 1:]:
                    if nxt.strip() and len(nxt) - len(nxt.lstrip()) <= base:
                        break
                    body.append(nxt)
                handlers[m.group(2)] = "\n".join(body)
    idx._handlers = handlers  # type: ignore[attr-defined]
    return handlers


def check_code(f: Finding, idx: CodebaseIndex) -> tuple[str, str, list[str]]:
    """Return (reachability, exposure, reasons) for a code or secret finding."""
    web = idx.is_web_service
    default_exposure = "internal"
    path = _resolve(f.path, idx)
    text = idx.sources.get(path)
    if text is None:
        return "unknown", "unknown", []

    lines = text.splitlines()
    line = lines[f.line - 1] if 1 <= f.line <= len(lines) else ""

    if f.tool == "secret" or _SECRET_RULE.search(f.rule_id):
        # a committed secret is exposed to anyone who can read the repo,
        # whether or not the code path runs
        return "reachable", "repository", ["secret is readable by anyone with access to the repo"]

    if path.endswith(".py"):
        fn = _function_at(lines, f.line)
        if fn is None:
            if "0.0.0.0" in line and web:
                return "reachable", "internet", ["module-level server config, listening on all interfaces"]
            return "reachable", default_exposure, ["runs at module level (on import)"]

        def_idx, name, params = fn
        if _is_py_handler(lines, def_idx, params, path):
            return "reachable", "internet", [f"inside route handler `{name}()`, reachable by any HTTP request"]

        handlers = _python_handlers(idx)
        callers = [h for h, body in handlers.items() if re.search(rf"\b{name}\s*\(", body)]
        if callers:
            return "reachable", "internet", [f"`{name}()` is called from route handler `{callers[0]}()`"]

        refs = sum(len(re.findall(rf"\b{name}\b", t)) for t in idx.sources.values())
        if refs <= 1:   # only its own definition
            return "not_called", default_exposure, [f"`{name}()` is never called anywhere in the repo"]
        return "unknown", default_exposure, [f"`{name}()` is used, but not directly from a route handler"]

    if path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")):
        window = "\n".join(lines[max(0, f.line - 40):f.line])
        if _JS_ROUTE.search(window):
            return "reachable", "internet", ["inside an HTTP route callback"]
        return "unknown", default_exposure, []

    return "unknown", "unknown", []


def _resolve(path: str, idx: CodebaseIndex) -> str:
    """Scanners report paths in different forms (absolute, relative to cwd,
    relative to the repo). Find the matching indexed source file."""
    if path in idx.sources:
        return path
    p = Path(path)
    for candidate in (p.resolve(), (idx.root / p).resolve()):
        if str(candidate) in idx.sources:
            return str(candidate)
    for known in idx.sources:
        if known.endswith("/" + path.replace("\\", "/").lstrip("./")):
            return known
    return path
