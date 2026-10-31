"""Offline report UI. Its HTTP authority is limited to one assessment service."""

from __future__ import annotations

import json
import secrets
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .service import ConflictError

MAX_BODY = 256 * 1024
_STATIC = Path(__file__).with_name("static")
_ASSETS = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}


def _bad_constant(_):
    raise ValueError("Non-finite JSON numbers are not supported")


def create_server(service, port=0):
    """Return an unstarted loopback server; callers must close it after use."""
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer between 0 and 65535")

    class Handler(BaseHTTPRequestHandler):
        server_version = "PAT"

        def _respond(self, status, data, content_type="application/json; charset=utf-8"):
            payload = (
                json.dumps(data, allow_nan=False).encode()
                if content_type.startswith("application/json")
                else data
            )
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'self'; script-src 'self'; style-src 'self'; "
                "img-src 'self'; object-src 'none'; base-uri 'none'; "
                "frame-ancestors 'none'; form-action 'self'",
            )
            self.end_headers()
            self.wfile.write(payload)

        def _error(self, status, message):
            self._respond(status, {"error": message})

        def _authorized_origin(self):
            # Exact Host validation also prevents DNS rebinding. There is no CORS.
            if self.headers.get("Host") != self.server.authority:
                self._error(403, "Unexpected report host")
                return False
            origin = self.headers.get("Origin")
            if origin is not None and origin != self.server.origin:
                self._error(403, "Unexpected report origin")
                return False
            if self.headers.get("Sec-Fetch-Site") == "cross-site":
                self._error(403, "Cross-site report requests are forbidden")
                return False
            return True

        def _query(self, query, key):
            values = parse_qs(query, strict_parsing=True)
            if set(values) != {key} or len(values[key]) != 1:
                raise ValueError(f"Expected one {key}")
            return values[key][0]

        def _parameters(self, query, required, optional, integers=()):
            if len(query) > 4096:
                raise ValueError("Report query is too long")
            values = parse_qs(query, strict_parsing=True, keep_blank_values=True)
            if not set(required) <= values.keys() or values.keys() - set(required) - set(optional):
                raise ValueError("Missing or unsupported report query parameters")
            if any(len(items) != 1 or not items[0] for items in values.values()):
                raise ValueError("Report query parameters require one nonempty value")
            result = {key: items[0] for key, items in values.items()}
            for key in integers:
                if key in result:
                    if not result[key].isascii() or not result[key].isdigit():
                        raise ValueError("Report query ranges require integer values")
                    result[key] = int(result[key])
            return result

        def _dispatch(self):
            if not self._authorized_origin():
                return
            parsed = urlsplit(self.path)
            if self.command == "GET":
                if parsed.path in _ASSETS and not parsed.query:
                    name, kind = _ASSETS[parsed.path]
                    self._respond(200, (_STATIC / name).read_bytes(), kind)
                    return
                if parsed.path == "/api/session" and not parsed.query:
                    result = {"token": self.server.token}
                elif parsed.path == "/api/projects" and not parsed.query:
                    result = service.list_projects()
                elif parsed.path == "/api/rubric" and not parsed.query:
                    result = service.rubric()
                elif parsed.path == "/api/analyzers" and not parsed.query:
                    from .analyzer_registry import list_analyzers

                    result = list_analyzers()
                elif parsed.path == "/api/report":
                    result = service.get_report(self._query(parsed.query, "assessment_id"))
                elif parsed.path == "/api/review-template":
                    result = service.review_template(self._query(parsed.query, "assessment_id"))
                elif parsed.path == "/api/evolve":
                    result = service.evolve(self._query(parsed.query, "assessment_id"))
                elif parsed.path == "/api/evidence-query":
                    parameters = self._parameters(
                        parsed.query,
                        {"assessment_id"},
                        {
                            "view",
                            "kind",
                            "path",
                            "role",
                            "candidate_kind",
                            "line",
                            "offset",
                            "limit",
                            "max_chars",
                        },
                        {"line", "offset", "limit", "max_chars"},
                    )
                    parameters.setdefault("max_chars", 16000)
                    if parameters["max_chars"] > 16000:
                        raise ValueError("Local evidence queries are limited to 16000 characters")
                    result = service.query_evidence(**parameters)
                elif parsed.path == "/api/source-context":
                    parameters = self._parameters(
                        parsed.query,
                        {"assessment_id", "evidence_id"},
                        {"line", "end_line", "max_chars"},
                        {"line", "end_line", "max_chars"},
                    )
                    result = service.source_context(**parameters)
                elif parsed.path == "/api/history":
                    result = service.history(self._query(parsed.query, "project_id"), summary=True)
                elif parsed.path == "/api/progress":
                    result = service.progress(self._query(parsed.query, "project_id"))
                else:
                    self._error(404, "Report route not found")
                    return
                self._respond(200, result)
                return
            if self.command != "POST":
                self._error(405, "Method not allowed")
                return
            if parsed.query or parsed.path not in {"/api/targets", "/api/scan", "/api/review"}:
                self._error(404, "Report route not found")
                return
            if self.headers.get("Origin") != self.server.origin or not secrets.compare_digest(
                self.headers.get("X-Project-Assess-Token", "").encode(), self.server.token.encode()
            ):
                self._error(403, "Report writes require this session's origin and token")
                return
            if self.headers.get_content_type() != "application/json":
                self._error(415, "Report writes require application/json")
                return
            if self.headers.get("Transfer-Encoding"):
                self._error(400, "Transfer encoding is unsupported")
                return
            try:
                size = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                size = -1
            if not 0 <= size <= MAX_BODY:
                self._error(413 if size > MAX_BODY else 400, "Invalid request body length")
                return
            body = self.rfile.read(size)
            if len(body) != size:
                raise ValueError("Incomplete request body")
            document = json.loads(body, parse_constant=_bad_constant)
            if not isinstance(document, dict):
                raise ValueError("Request body must be a JSON object")
            if parsed.path == "/api/targets":
                if not {"project_id", "targets", "expected_revision"} <= document.keys():
                    raise ValueError("Targets require project_id, targets, and expected_revision")
                if document.keys() - {
                    "project_id",
                    "targets",
                    "expected_revision",
                    "profile",
                    "request_id",
                }:
                    raise ValueError("Unsupported target fields")
                result = service.set_targets(**document)
            elif parsed.path == "/api/review":
                if (
                    not {"assessment_id", "review"} <= document.keys()
                    or document.keys() - {"assessment_id", "review", "request_id"}
                    or not isinstance(document["assessment_id"], str)
                    or not isinstance(document["review"], dict)
                ):
                    raise ValueError(
                        "Review requires assessment_id, review, and optional request_id"
                    )
                result = service.submit_review(**document)
            else:
                identity_fields = document.keys() - {"analysis_profile", "analyzers"}
                if identity_fields == {"root"} and isinstance(document["root"], str):
                    root = document["root"]
                    if not root or len(root) > 4096 or "\x00" in root:
                        raise ValueError("Scan root must be a nonempty project directory path")
                elif identity_fields == {"project_id"} and isinstance(document["project_id"], str):
                    project = next(
                        (p for p in service.list_projects() if p["id"] == document["project_id"]),
                        None,
                    )
                    if project is None:
                        self._error(404, "Project not found")
                        return
                    root = project["root"]
                else:
                    raise ValueError("Scan requires either root or project_id")
                try:
                    result = service.scan(
                        root,
                        analysis_profile=document.get("analysis_profile", "standard"),
                        analyzers=document.get("analyzers"),
                    )
                except (FileNotFoundError, NotADirectoryError):
                    raise ValueError("Project root must be an existing directory") from None
            self._respond(200, result)

        def _handle(self):
            self.connection.settimeout(10)
            try:
                self._dispatch()
            except ConflictError as exc:
                self._error(409, str(exc))
            except PermissionError as exc:
                self._error(403, str(exc))
            except ValueError as exc:
                self._error(400, str(exc))
            except Exception:
                # Internal diagnostics must not spill filesystem or source data into responses.
                self._error(500, "Report request failed")

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _handle

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    server.authority = f"127.0.0.1:{server.server_port}"
    server.origin = f"http://{server.authority}"
    server.token = secrets.token_urlsafe(32)
    return server


def serve(service, port=0, open_browser=False):
    """Run the local UI until interrupted, without changing host configuration."""
    with create_server(service, port) as server:
        print(f"PAT: {server.origin}", flush=True)
        if open_browser:
            webbrowser.open(server.origin)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
