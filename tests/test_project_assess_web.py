"""Local report transport boundaries; no cloud access or target execution."""

from __future__ import annotations

import http.client
import json
import threading
from copy import deepcopy

import pytest

from project_assess.service import AssessmentService, ConflictError
from project_assess.web import MAX_BODY, create_server


class Service:
    def __init__(self):
        self.revision = 0
        self.scans = []
        self.calls = []
        self.targets = None
        self.history_calls = []

    def list_projects(self):
        return [
            {
                "id": "p1",
                "root": "/registered/source",
                "name": "<script>window.pwned=1</script>",
                "latest_assessment_id": "a1",
                "goal_revision": self.revision,
            }
        ]

    def rubric(self):
        return {"version": "1", "dimensions": {}, "profiles": {}}

    def get_report(self, assessment_id):
        if assessment_id != "a1":
            raise ValueError("Assessment not found")
        return {"assessment": {"id": assessment_id}, "review": None, "goals": self.targets}

    def history(self, project_id, *, summary=False):
        self.history_calls.append((project_id, summary))
        return {"assessments": [], "reviews": [], "goals": []}

    def progress(self, project_id):
        return {"project_id": project_id, "event": "goal_baseline"}

    def set_targets(self, **document):
        self.calls.append(deepcopy(document))
        if document["expected_revision"] != self.revision:
            raise ConflictError("Targets changed in another session")
        self.revision += 1
        self.targets = {"revision": self.revision, "targets": document["targets"]}
        return self.targets

    def scan(self, root):
        self.scans.append(root)
        return {"id": "a2"}


@pytest.fixture
def running_report():
    service = Service()
    with create_server(service) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield service, server
        server.shutdown()
        thread.join(timeout=5)


def request(server, method="GET", path="/", document=None, headers=None, body=None):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    if document is not None:
        body = json.dumps(document).encode()
    default = {}
    if method == "POST":
        default = {
            "Origin": server.origin,
            "X-Project-Assess-Token": server.token,
            "Content-Type": "application/json",
        }
    default.update(headers or {})
    connection.request(method, path, body=body, headers=default)
    response = connection.getresponse()
    payload = response.read()
    result = response.status, dict(response.getheaders()), payload
    connection.close()
    return result


def test_report_bootstrap_assets_and_session(running_report):
    _, server = running_report
    assert server.server_address[0] == "127.0.0.1"
    status, headers, body = request(server)
    assert status == 200 and b"<h1>PAT</h1>" in body
    assert b"Project Assessment Toolkit" in body and b"pat --state-dir" in body
    assert "frame-ancestors 'none'" in headers["Content-Security-Policy"]
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert headers["Cache-Control"] == "no-store"
    assert "Access-Control-Allow-Origin" not in headers
    for asset in ("/app.js", "/style.css"):
        assert request(server, path=asset)[0] == 200
    session = json.loads(request(server, path="/api/session")[2])
    assert session["token"] == server.token
    assert len(session["token"]) >= 32
    projects = json.loads(request(server, path="/api/projects")[2])
    assert projects[0]["name"].startswith("<script>")


@pytest.mark.parametrize(
    "headers",
    [
        {"Host": "attacker.example"},
        {"Origin": "https://attacker.example"},
        {"Origin": "null"},
        {"Sec-Fetch-Site": "cross-site"},
    ],
)
def test_session_rejects_rebinding_and_cross_site_reads(running_report, headers):
    _, server = running_report
    assert request(server, path="/api/session", headers=headers)[0] == 403


@pytest.mark.parametrize(
    "headers",
    [
        {"Origin": "https://attacker.example"},
        {"Origin": ""},
        {"X-Project-Assess-Token": ""},
        {"X-Project-Assess-Token": "wrong"},
    ],
)
def test_target_writes_require_exact_origin_and_session_token(running_report, headers):
    service, server = running_report
    document = {"project_id": "p1", "targets": {}, "expected_revision": 0}
    assert request(server, "POST", "/api/targets", document, headers)[0] == 403
    assert service.calls == []


def test_target_write_and_stale_revision_conflict(running_report):
    service, server = running_report
    document = {"project_id": "p1", "targets": {"testing": {}}, "expected_revision": 0}
    status, _, body = request(server, "POST", "/api/targets", document)
    assert status == 200
    assert json.loads(body)["revision"] == 1
    assert request(server, "POST", "/api/targets", document)[0] == 409
    assert service.revision == 1


@pytest.mark.parametrize(
    ("body", "headers", "expected"),
    [
        (b"{}", {"Content-Type": "text/plain"}, 415),
        (b"{", {}, 400),
        (b"[]", {}, 400),
        (b'{"number": NaN}', {}, 400),
        (b"{}", {"Content-Length": str(MAX_BODY + 1)}, 413),
        (b"{}", {"Transfer-Encoding": "chunked"}, 400),
        (b'{"project_id":"p1","targets":{}}', {}, 400),
    ],
)
def test_bounded_strict_json_writes(running_report, body, headers, expected):
    service, server = running_report
    assert request(server, "POST", "/api/targets", body=body, headers=headers)[0] == expected
    assert service.calls == []


def test_no_arbitrary_paths_or_source_roots(running_report):
    service, server = running_report
    for path in ("/../pyproject.toml", "/static/../../pyproject.toml", "/app.js?path=/etc/passwd"):
        assert request(server, path=path)[0] == 404
    assert (
        request(server, "POST", "/api/scan", {"project_id": "p1", "root": "/elsewhere"})[0] == 400
    )
    assert request(server, "POST", "/api/scan", {"project_id": "absent"})[0] == 404
    assert request(server, "POST", "/api/scan", {"project_id": "p1"})[0] == 200
    assert service.scans == ["/registered/source"]


def test_query_contract_and_method_rejection(running_report):
    service, server = running_report
    assert request(server, path="/api/report?assessment_id=a1")[0] == 200
    assert request(server, path="/api/report?assessment_id=a1&assessment_id=a2")[0] == 400
    assert request(server, path="/api/report?path=/etc/passwd")[0] == 400
    assert request(server, path="/api/history?project_id=p1")[0] == 200
    assert service.history_calls == [("p1", True)]
    assert request(server, path="/api/progress?project_id=p1")[0] == 200
    assert request(server, "PUT", "/api/targets")[0] == 405


@pytest.mark.parametrize(
    ("error", "status", "message"),
    [
        (ConflictError("Goals changed"), 409, "Goals changed"),
        (PermissionError("Root is no longer allowed"), 403, "Root is no longer allowed"),
        (ValueError("Unknown assessment ID"), 400, "Unknown assessment ID"),
        (RuntimeError("private-diagnostic"), 500, "Report request failed"),
        (LookupError("private-diagnostic"), 500, "Report request failed"),
        (KeyError("private-diagnostic"), 500, "Report request failed"),
    ],
)
def test_transport_uses_typed_errors_and_sanitizes_internal_failures(
    running_report, monkeypatch, error, status, message
):
    service, server = running_report

    def fail(_):
        raise error

    monkeypatch.setattr(service, "get_report", fail)
    actual_status, _, body = request(server, path="/api/report?assessment_id=a1")
    assert actual_status == status
    assert json.loads(body) == {"error": message}
    assert b"private-diagnostic" not in body


def test_real_history_response_omits_snapshot_bodies_and_reports_retain_selected_evidence(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "README.md"
    source.write_text("# Project\nFirst captured content.\n")
    service = AssessmentService(tmp_path / "state")
    first = service.scan(root)
    review = service.submit_review(first["id"], service.review_template(first["id"]))
    goals = service.set_targets(
        first["project_id"], profile="internal-service", expected_revision=0
    )
    source.write_text("# Project\nNew captured content.\n")
    second = service.scan(root)

    with create_server(service) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, _, body = request(server, path="/api/history?project_id=" + first["project_id"])
            assert status == 200
            history = json.loads(body)
            assert history == {
                "assessments": [
                    {"id": snapshot["id"], "created_at": snapshot["created_at"]}
                    for snapshot in (first, second)
                ],
                "reviews": [{key: review[key] for key in ("id", "assessment_id", "created_at")}],
                "goals": [{key: goals[key] for key in ("revision", "created_at")}],
            }
            for excluded in (b"facts", b"excerpt", b"targets", b"First captured content"):
                assert excluded not in body
            conflict_status, _, conflict_body = request(
                server,
                "POST",
                "/api/targets",
                {
                    "project_id": first["project_id"],
                    "targets": goals["targets"],
                    "expected_revision": 0,
                },
            )
            assert conflict_status == 409
            assert json.loads(conflict_body) == {"error": "Goals changed; reload before saving"}
            report_status, _, report_body = request(
                server, path="/api/report?assessment_id=" + first["id"]
            )
            assert report_status == 200
            assert json.loads(report_body)["assessment"] == first
            assert b"First captured content" in report_body
            assert service.history(first["project_id"])["assessments"] == [first, second]
        finally:
            server.shutdown()
            thread.join(timeout=5)
