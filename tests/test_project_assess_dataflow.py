"""Joern paths remain attributable evidence, including failed and bounded phases."""

import copy
import hashlib
import json

import pytest

from project_assess.joern_dataflow import normalize_dataflow


def section(rows):
    return {"status": "complete", "count": len(rows), "omitted": 0, "rows": rows}


@pytest.fixture
def flow(tmp_path):
    stage = tmp_path / "source"
    sources = {}
    for path, text in {
        "src/start.py": "def start(value):\n    return finish(value)\n",
        "src/finish.py": "def finish(value):\n    return value\n",
    }.items():
        sources[path] = {
            "lines": text.splitlines(),
            "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
            "evidence_id": "e-" + path,
        }

    def node(path, line, name, method, kind):
        return {
            "path": str(stage / path),
            "line": line,
            "name": name,
            "method": str(stage / path) + ":" + method,
            "node_type": kind,
        }

    steps = [
        node("src/start.py", 1, "value", "start", "METHOD_PARAMETER_IN"),
        node("src/start.py", 2, "finish", "start", "CALL"),
        node("src/finish.py", 1, "value", "finish", "METHOD_PARAMETER_IN"),
        node("src/finish.py", 2, "return", "finish", "METHOD_RETURN"),
    ]
    raw = {
        "dataflow": "complete",
        "dataflow_analysis": {
            "status": "complete",
            "max_definitions": 50_000,
            "maximum_definitions_observed": 5001,
            "max_call_depth": 8,
            "methods_total": 2,
            "methods_analyzed": 2,
            "methods_skipped": 0,
            "skipped_methods": section([]),
            "paths": {
                **section(
                    [
                        {
                            "kind": "parameter_to_return",
                            "source": steps[0],
                            "sink": steps[-1],
                            "steps": steps,
                            "interprocedural": True,
                        }
                    ]
                ),
                "count_is_lower_bound": False,
            },
            "queries": {
                "sinks_total": 2,
                "sinks_queried": 2,
                "sinks_omitted": 0,
                "paths_truncated": 0,
                "step_limit": 64,
            },
        },
    }
    return raw, stage, sources


def normalize(flow, **kwargs):
    raw, stage, sources = flow
    return normalize_dataflow(raw, stage=stage, sources=sources, clean=kwargs.get("clean", str))


def test_cross_file_paths_bind_every_step_to_original_source(flow):
    raw = copy.deepcopy(flow[0])
    result, gaps = normalize(flow)
    assert gaps == set()
    assert result["status"] == "complete"
    assert result["maximum_definitions_observed"] == 5001
    path = result["paths"]["rows"][0]
    assert path["interprocedural"]
    assert {node["path"] for node in path["steps"]} == {"src/start.py", "src/finish.py"}
    for node in [path["source"], path["sink"], *path["steps"]]:
        source = flow[2][node["path"]]
        assert node["source_evidence_id"] == source["evidence_id"]
        assert node["digest"] == source["digest"]
    assert str(flow[1]) not in json.dumps(result)
    assert flow[0] == raw
    assert "not runtime traces" in result["caveat"]


def test_path_identity_survives_workspace_relocation_but_not_source_changes(flow, tmp_path):
    first, _ = normalize(flow)
    raw, stage, sources = flow
    relocated = tmp_path / "relocated" / "source"
    changed = json.loads(json.dumps(raw).replace(str(stage), str(relocated)))
    second, _ = normalize((changed, relocated, sources))
    assert first["paths"]["rows"][0]["id"] == second["paths"]["rows"][0]["id"]
    updated_sources = copy.deepcopy(sources)
    updated_sources["src/finish.py"]["digest"] = "sha256:" + "a" * 64
    third, _ = normalize((changed, relocated, updated_sources))
    assert first["paths"]["rows"][0]["id"] != third["paths"]["rows"][0]["id"]


@pytest.mark.parametrize(
    "path",
    ["../outside.py", "/outside.py", "src/../outside.py", "src\\start.py", "src/start.py\x00"],
)
def test_unbound_source_paths_are_omitted_without_leaking_producer_text(flow, path):
    bad = flow[0]["dataflow_analysis"]["paths"]["rows"][0]
    bad["steps"][1]["path"] = path
    bad["steps"][1]["name"] = "SECRET-PRODUCER-TEXT"
    result, gaps = normalize(flow)
    assert result["status"] == "partial"
    assert result["paths"]["rows"] == []
    assert result["paths"]["omitted"] == 1
    assert gaps
    assert "SECRET-PRODUCER-TEXT" not in json.dumps(result)


@pytest.mark.parametrize("change", ["line", "endpoint", "procedure", "length", "kind"])
def test_source_and_flow_inconsistencies_do_not_become_evidence(flow, change):
    row = flow[0]["dataflow_analysis"]["paths"]["rows"][0]
    if change == "line":
        row["steps"][1]["line"] = 99
    elif change == "endpoint":
        row["source"] = row["sink"]
    elif change == "procedure":
        row["interprocedural"] = False
    elif change == "length":
        row["steps"] *= 17
    else:
        row["kind"] = "confirmed_vulnerability"
    result, gaps = normalize(flow)
    assert gaps and result["status"] == "partial"
    assert result["paths"]["rows"] == []


@pytest.mark.parametrize("counter", [True, -1, float("nan"), float("inf"), 2**53 + 1])
def test_invalid_aggregate_counts_are_rejected(flow, counter):
    flow[0]["dataflow_analysis"]["methods_total"] = counter
    with pytest.raises(ValueError, match="counter"):
        normalize(flow)


@pytest.mark.parametrize("field", ["methods", "sinks", "rows", "phase", "definitions"])
def test_inconsistent_coverage_claims_are_rejected(flow, field):
    value = flow[0]["dataflow_analysis"]
    if field == "methods":
        value["methods_analyzed"] = 1
    elif field == "sinks":
        value["queries"]["sinks_queried"] = 1
    elif field == "rows":
        value["paths"]["omitted"] = 1
    elif field == "phase":
        value["status"] = "partial"
    else:
        value["maximum_definitions_observed"] = 50_001
    with pytest.raises(ValueError):
        normalize(flow)


def test_skipped_large_method_preserves_its_source_location_and_definitions(flow):
    value = flow[0]["dataflow_analysis"]
    flow[0]["dataflow"] = value["status"] = "partial"
    value["maximum_definitions_observed"] = 50_001
    value["methods_analyzed"] = 1
    value["methods_skipped"] = 1
    value["skipped_methods"] = section(
        [
            {
                "path": "src/start.py",
                "line": 1,
                "method": "start",
                "definitions": 50_001,
                "reason": "definition_limit",
            }
        ]
    )
    result, gaps = normalize(flow)
    assert result["status"] == "partial"
    skipped = result["skipped_methods"]["rows"][0]
    assert skipped["source_evidence_id"] == "e-src/start.py"
    assert skipped["definitions"] == 50_001
    assert any("definition limit" in gap for gap in gaps)


def test_bounded_queries_cannot_claim_complete_even_when_every_retained_row_is_valid(flow):
    queries = flow[0]["dataflow_analysis"]["queries"]
    queries.update(sinks_queried=1, sinks_omitted=1, paths_truncated=1)
    result, gaps = normalize(flow)
    assert result["status"] == "partial"
    assert result["paths"]["rows"]
    assert any("queries were bounded" in gap for gap in gaps)


def test_duplicate_paths_are_visible_and_do_not_inflate_retained_evidence(flow):
    paths = flow[0]["dataflow_analysis"]["paths"]
    paths["rows"] *= 2
    paths["count"] = 2
    result, gaps = normalize(flow)
    assert len(result["paths"]["rows"]) == 1
    assert result["paths"]["count"] == 2
    assert result["paths"]["omitted"] == 1
    assert result["normalization_omissions"] == {"duplicate_path": 1}
    assert gaps


def test_not_run_and_failed_phases_are_not_successful_empty_checks(flow):
    _, stage, sources = flow
    standard, gaps = normalize_dataflow(
        {"dataflow": "not_run"}, stage=stage, sources=sources, clean=str
    )
    assert standard["status"] == "not_run" and standard["paths"]["count"] is None
    assert not gaps
    failed, gaps = normalize_dataflow(
        {"dataflow": "error", "dataflow_analysis": {"status": "error", "error": "SECRET"}},
        stage=stage,
        sources=sources,
        clean=str,
    )
    assert failed["status"] == "error" and failed["paths"]["count"] is None
    assert gaps and "SECRET" not in json.dumps(failed)
    with pytest.raises(ValueError, match="unrun"):
        normalize_dataflow(
            {"dataflow": "not_run", "dataflow_analysis": flow[0]["dataflow_analysis"]},
            stage=stage,
            sources=sources,
            clean=str,
        )


def test_node_fields_are_redacted_and_unrecognized_payload_is_not_retained(flow):
    for node in flow[0]["dataflow_analysis"]["paths"]["rows"][0]["steps"]:
        node["code"] = "SECRET-CODE"
    result, _ = normalize(flow, clean=lambda text: text.replace("value", "<redacted>"))
    encoded = json.dumps(result)
    assert "SECRET-CODE" not in encoded
    assert "<redacted>" in encoded
    assert "value" not in json.dumps(result["paths"]["rows"])
