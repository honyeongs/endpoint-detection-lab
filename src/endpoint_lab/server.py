from pathlib import Path

from .analysis import analyze_bytes
from .catalog import RULES
from .http_security import LocalServer, SecureHandler
from .limits import DEFAULT, InputError
from .scenarios import get_case, scenario_catalog, tuned_policy
from .validation import compare_policies

ROOT = Path(__file__).parent / "web"
STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
for name in ["app", "render", "timeline", "processes", "verification", "transport"]:
    STATIC[f"/{name}.js"] = (name + ".js", "text/javascript; charset=utf-8")
for name in ["shield-check", "upload", "download", "play", "pause", "skip-forward", "rotate-ccw", "search", "git-branch", "list", "flask-conical", "file-code", "x"]:
    STATIC[f"/assets/{name}.svg"] = ("assets/" + name + ".svg", "image/svg+xml")


class Handler(SecureHandler):
    def do_GET(self):
        if not self.host_valid():
            return self.json(403, {"error": "Host rejected."})
        if self.path == "/api/health":
            return self.json(200, {"status": "ready", "max_file_bytes": DEFAULT.file_bytes})
        if self.path == "/api/catalog":
            return self.json(200, {"rules": RULES, "scenarios": scenario_catalog()})
        if self.path == "/api/validation":
            return self.json(200, compare_policies())
        if self.path.startswith("/api/scenarios/"):
            case = get_case(self.path.removeprefix("/api/scenarios/"))
            return self.json(200, case) if case else self.json(404, {"error": "Unknown scenario."})
        if self.path not in STATIC:
            return self.json(404, {"error": "Not found."})
        name, mime = STATIC[self.path]
        self.respond(200, (ROOT / name).read_bytes(), mime)

    def do_POST(self):
        if not self.host_valid() or self.headers.get_all("Origin", []) != [self.origin]:
            return self.json(403, {"error": "Same-origin loopback requests only."})
        if self.path != "/api/analyze":
            return self.json(404, {"error": "Not found."})
        try:
            selected = self.headers.get("X-Lab-Policy", "baseline")
            if selected not in {"baseline", "tuned"}:
                raise InputError("Unknown policy preset.")
            count = self.headers.get("X-Replay-Count")
            if count is not None and (len(count) > 5 or not count.isascii() or not count.isdecimal()):
                raise InputError("Invalid replay count.")
            result = analyze_bytes(self.read_body(), policy=tuned_policy() if selected == "tuned" else None,
                                   replay_count=int(count) if count is not None else None)
            self.json(200, result)
        except InputError as exc:
            self.json(400, {"error": str(exc)})
        except TimeoutError:
            self.json(408, {"error": "Request body timed out."})


def create_server(port=8894):
    if not isinstance(port, int) or not 0 <= port <= 65535:
        raise InputError("Port must be between 0 and 65535.")
    return LocalServer(("127.0.0.1", port), Handler)


def serve_local(port=8894):
    with create_server(port) as server:
        print(f"Endpoint Lab: http://127.0.0.1:{server.server_port}/", flush=True)
        server.serve_forever(poll_interval=0.25)
