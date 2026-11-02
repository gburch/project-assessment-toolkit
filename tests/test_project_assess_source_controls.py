"""Source controls are located syntax observations, not proven quality or vulnerabilities."""

import ast
import json

import pytest

from project_assess.source_controls import analyze_python_controls


def scan(source, **kwargs):
    return analyze_python_controls("src/sample.py", ast.parse(source), **kwargs)


def signals(result, kind):
    return [row for row in result["signals"] if row["kind"] == kind]


def test_timing_assertions_are_review_leads_without_claiming_margin_or_flakiness():
    result = scan("""import time as clock
def test_speed(self):
    assert elapsed < .1, "private assertion message"
    assert clock.perf_counter() - started < limit
    self.assertLess(result.duration_ms, limit)
    assert limit > latency
    assert count < 2
    assert timeout < 2
    assert opaque_measurement() < 2
    assert elapsed is None
    assert duration in allowed_values
""")
    rows = signals(result, "performance.timing_threshold_hint")
    assert [row["locations"][0]["line"] for row in rows] == [3, 4, 5, 6]
    assert rows[1]["context"]["measurement_basis"] == "clock_difference"
    assert rows[0]["context"]["threshold_shape"] == "positive_literal"
    assert "private assertion message" not in json.dumps(result)
    assert all(row["confidence"] == "low" for row in rows)
    assert all(row["dimensions"] == ["performance"] for row in rows)
    assert all(
        row["context"][key] == "unestablished"
        for row in rows
        for key in ("headroom", "variance", "gating")
    )
    assert not signals(
        scan("""import time as clock
def test_speed(clock):
    assert clock.perf_counter() - started < 1
"""),
        "performance.timing_threshold_hint",
    )


def test_timing_lead_retention_is_bounded_and_deterministic():
    source = "\n".join(f"assert elapsed < {i + 1}" for i in range(20))
    result = scan(source, signal_limit=3)
    assert result == scan(source, signal_limit=3)
    assert result["coverage"]["signals_found"] == 20
    assert len(result["signals"]) == 3
    assert result["coverage"]["signals_omitted"] == 17
    assert result["status"] == "partial"


def test_security_alias_binding_and_conservative_shadowing():
    result = scan("""import subprocess as process
from pickle import loads as decode
process.run(command, shell=True)
decode(payload)
eval(expression)
def scoped(process, decode, eval):
    process.run(command, shell=True)
    decode(payload)
    eval(expression)
""")
    assert len(signals(result, "security.shell_execution")) == 1
    assert len(signals(result, "security.object_deserialization")) == 1
    assert len(signals(result, "security.dynamic_code_execution")) == 1
    shell = signals(result, "security.shell_execution")[0]
    assert shell["locations"] == [{"path": "src/sample.py", "line": 3, "end_line": 3}]
    assert shell["context"]["callee"] == "subprocess.run"
    assert shell["context"]["category"] == "risk_candidate"


@pytest.mark.parametrize(
    "source",
    [
        "def eval(value): return value\neval(expression)",
        "import subprocess\nsubprocess = replacement\nsubprocess.run(command, shell=True)",
        "import subprocess\nsubprocess.run = replacement\nsubprocess.run(command, shell=True)",
        "from anything import *\neval(expression)",
    ],
)
def test_redefinitions_and_wildcards_do_not_become_resolved_security_findings(source):
    result = scan(source)
    assert not signals(result, "security.shell_execution")
    assert not signals(result, "security.dynamic_code_execution")


def test_yaml_loader_tls_comparison_and_query_shapes_do_not_claim_exploitability():
    result = scan("""import yaml as y
from yaml import SafeLoader as Safe
from hmac import compare_digest as equal
import requests as http
y.load(data, Loader=Safe)
y.load(data, Safe)
y.load(data)
equal(left, right)
http.get(url, verify=False)
cursor.execute(f"SELECT * FROM things WHERE name={name}")
cursor.execute("SELECT * FROM things WHERE name=?", (name,))
""")
    loaders = signals(result, "security.yaml_loader")
    assert [row["context"]["loader"] for row in loaders] == [
        "safe_loader",
        "safe_loader",
        "unestablished_loader",
    ]
    assert loaders[-1]["context"]["category"] == "risk_candidate"
    assert signals(result, "security.constant_time_comparison")
    assert signals(result, "security.tls_verification_argument")[0]["context"]["verify"] == "false"
    assert (
        signals(result, "security.interpolated_execute_hint")[0]["context"]["binding"]
        == "unresolved_name"
    )
    assert signals(result, "security.separate_query_parameters_hint")
    assert all("capability" not in row and "severity" not in row for row in result["signals"])


def test_io_loop_context_excludes_iterable_calls_and_nested_functions():
    result = scan("""from requests import get as fetch
for item in fetch(url):
    fetch(item, timeout=3)
    def later():
        fetch(url)
while fetch(url):
    break
values = [fetch(item) for item in items]
""")
    calls = signals(result, "performance.io_call")
    assert [(row["locations"][0]["line"], row["context"]["in_loop"]) for row in calls] == [
        (2, False),
        (3, True),
        (5, False),
        (6, True),
        (8, True),
    ]
    assert len(signals(result, "performance.io_in_loop")) == 3
    assert calls[1]["context"]["timeout"] == "positive_literal"
    assert calls[0]["context"]["timeout"] == "absent_on_call"


def test_mechanisms_and_unresolved_operational_hints_are_distinct():
    result = scan("""import logging
import time as clock
from tenacity import retry
@retry()
def healthcheck():
    try:
        fetch()
    except Exception:
        logger.exception("secret payload", extra={"request_id": request_id})
        clock.sleep(2)
        store.checkpoint()
logging.warning("message")
""")
    logging_rows = signals(result, "operability.logging")
    assert logging_rows[0]["context"]["category"] == "name_hint"
    assert logging_rows[0]["context"]["in_exception_handler"]
    assert logging_rows[0]["context"]["structured_context"]
    assert logging_rows[1]["context"]["category"] == "mechanism"
    assert signals(result, "operability.health_entrypoint_hint")
    assert signals(result, "operability.retry_policy")
    assert (
        signals(result, "operability.recovery_call_hint")[0]["context"]["category"] == "name_hint"
    )
    assert "secret payload" not in json.dumps(result)


def test_function_defaults_and_decorators_keep_enclosing_evaluation_context():
    result = scan("""import requests
for item in items:
    @requests.get(url)
    def later(requests=requests.get(url)):
        requests.get(url)
    class Declared:
        response = requests.get(url)
""")
    calls = signals(result, "performance.io_call")
    assert {row["locations"][0]["line"] for row in calls} == {3, 4, 7}
    assert all(row["context"]["in_loop"] for row in calls)


def test_extensibility_and_performance_controls_include_known_decorators():
    result = scan("""from typing import Protocol as Contract, Callable
from abc import abstractmethod
from functools import cache, lru_cache, singledispatch
from importlib.metadata import entry_points
from asyncio import Queue, Semaphore
class Backend(Contract):
    @abstractmethod
    def execute(self): ...
class Service:
    def __init__(self, handler: Callable, client: Backend):
        self.handler = handler
@cache
def lookup(): return 1
@lru_cache(maxsize=10)
def other(): return 2
@singledispatch
def dispatch(value): return value
entry_points()
registry.register("private-name", Backend)
queue = Queue(maxsize=10)
slots = Semaphore(3)
""")
    assert signals(result, "extensibility.interface")[0]["context"]["bases"] == ["typing.Protocol"]
    assert len(signals(result, "extensibility.injected_parameter_hint")) == 2
    assert len(signals(result, "extensibility.dispatch_or_abstract_declaration")) == 2
    assert signals(result, "extensibility.discovery_or_dispatch")
    assert signals(result, "extensibility.registration_hint")
    assert len(signals(result, "performance.cache_declaration")) == 2
    assert [
        row["context"]["configured_bound"]
        for row in signals(result, "performance.admission_or_concurrency_control")
    ] == ["positive_literal", "positive_literal"]
    assert "private-name" not in json.dumps(result)


def test_delivery_process_flags_and_multiline_locations_preserve_no_command_text():
    result = scan("""from subprocess import run as launch
launch(
    ["package-tool", "--locked", "private-token-value"],
    check=True,
    timeout=120,
)
launch(["git", "rev-parse", "--verify", "HEAD"], check=True)
launch(dynamic_command)
""")
    rows = signals(result, "delivery.process_launch")
    assert rows[0]["locations"][0] == {"path": "src/sample.py", "line": 2, "end_line": 6}
    assert rows[0]["context"]["command_form"] == "literal_argv"
    assert rows[0]["context"]["known_flags"] == ["--locked"]
    assert rows[0]["context"]["check"] == "true"
    assert rows[1]["context"]["revision_query"]
    assert rows[2]["context"]["command_form"] == "expression"
    assert not rows[2]["context"]["revision_query"]
    assert "private-token-value" not in json.dumps(result)
    assert "package-tool" not in json.dumps(result)


def test_retention_is_bounded_by_kind_and_reports_omitted_observations():
    source = "import logging, subprocess\n" + "logging.info(value)\n" * 200
    source += "subprocess.run(command, shell=True)\n"
    result = scan(source, signal_limit=5)
    assert len(result["signals"]) == 5
    assert signals(result, "security.shell_execution")
    assert signals(result, "delivery.process_launch")
    assert result["coverage"]["signals_found"] > 200
    assert result["coverage"]["signals_omitted"] == result["coverage"]["signals_found"] - 5
    assert result["status"] == "partial"
    assert result == scan(source, signal_limit=5)


def test_node_limit_keeps_partial_binding_unknown_without_absence_claims():
    result = scan("import subprocess\nsubprocess.run(command, shell=True)\n", node_limit=2)
    assert result["coverage"]["nodes_examined"] == 2
    assert result["coverage"]["node_limit_reached"]
    assert result["status"] == "partial"
    assert not signals(result, "security.shell_execution")


def test_safe_loader_flood_preserves_the_lone_unknown_loader_candidate():
    source = "import yaml\n" + "yaml.load(payload, Loader=yaml.SafeLoader)\n" * 300
    source += "yaml.load(payload)\n"
    result = scan(source, signal_limit=2)
    loaders = signals(result, "security.yaml_loader")
    assert {row["context"]["category"] for row in loaders} == {"mechanism", "risk_candidate"}
    assert result["signal_counts"]["security.yaml_loader"] == 301
    assert result["coverage"]["signals_omitted"] == 299
    assert result == scan(source, signal_limit=2)


def test_enabled_tls_flood_preserves_disabled_check_under_a_tight_cap():
    source = "import requests\n" + "requests.get(url, verify=True)\n" * 300
    source += 'requests.get("private-url-never-retained", verify=False)\n'
    result = scan(source, signal_limit=3)
    tls = signals(result, "security.tls_verification_argument")
    assert {row["context"]["verify"] for row in tls} == {"true", "false"}
    assert result["signal_counts"]["security.tls_verification_argument"] == 301
    assert result["coverage"]["signals_found"] == 602
    assert result["coverage"]["signals_omitted"] == 599
    smallest = scan(source, signal_limit=1)
    assert smallest["signals"][0]["context"]["category"] == "risk_candidate"
    assert "private-url-never-retained" not in json.dumps(result)


def test_no_project_code_is_executed():
    result = scan("raise RuntimeError('must never run')\nimport missing_private_dependency\n")
    assert result["coverage"]["nodes_examined"] > 0
    assert result["signals"] == []


def test_query_and_fetch_hints_preserve_loop_scope_without_sql_text():
    result = scan("""def load(cursor, values):
    cursor.execute("private-query-body", params=values)
    for value in values:
        cursor.execute(f"private-query-{value}")
        cursor.fetchall()
        cursor.fetchmany(size=50)
        def later():
            cursor.executemany(query, rows)
""")
    query_rows = signals(result, "performance.query_call_hint")
    assert [row["context"]["in_loop"] for row in query_rows] == [False, True, False]
    assert query_rows[0]["context"]["separate_parameters"]
    assert query_rows[1]["context"]["interpolated_argument"]
    assert all(row["context"]["category"] == "name_hint" for row in query_rows)
    fetched = signals(result, "performance.result_materialization_hint")
    assert [row["context"]["fetch_mode"] for row in fetched] == ["all_rows", "batch_rows"]
    assert all(row["context"]["in_loop"] for row in fetched)
    assert fetched[1]["context"]["batch_bound"] == "positive_literal"
    assert "private-query" not in json.dumps(result)
    assert not signals(
        scan("cursor.rowcount\ngetattr(cursor, method)(query)"), "performance.query_call_hint"
    )


def test_exception_body_flags_describe_direct_syntax_only():
    result = scan("""def run():
    try: work()
    except One: pass
    except Two: return fallback
    except Three: raise
    except Four: raise Replacement()
    except Five:
        if condition: return nested
""")
    rows = signals(result, "operability.exception_boundary")
    assert [row["context"]["pass_only"] for row in rows] == [True, False, False, False, False]
    assert [row["context"]["direct_return"] for row in rows] == [False, True, False, False, False]
    assert [row["context"]["direct_raise"] for row in rows] == [False, False, True, True, False]
    assert [row["context"]["bare_reraise"] for row in rows] == [False, False, True, False, False]


def test_synchronization_and_transaction_contexts_keep_resolution_explicit():
    result = scan("""from threading import Lock as Mutex
def run(self):
    with Mutex(): work()
    with self._lock: work()
    with store.transaction(): work()
    with open(path): work()
async def other(self):
    async with self._mutex: await work()
""")
    locks = signals(result, "performance.synchronization_context_hint")
    assert [row["context"]["category"] for row in locks] == ["mechanism", "name_hint", "name_hint"]
    assert locks[0]["context"]["constructed_in_context"]
    assert locks[-1]["context"]["asynchronous"]
    assert len(signals(result, "performance.transaction_context_hint")) == 1
    assert not signals(result, "operability.retry_policy")
    assert (
        signals(result, "performance.admission_or_concurrency_control")[0]["context"][
            "configured_bound"
        ]
        == "mutex_constructor"
    )
    assert not signals(
        scan("lock = variable\nwith clock(): pass"), "performance.synchronization_context_hint"
    )


def test_authorization_declarations_and_gate_names_are_not_effectiveness_claims():
    result = scan("""from flask_login import login_required as protect
from django.contrib.auth.decorators import permission_required
from local.auth import require_approval as gate
@protect
def page(): pass
@permission_required("private-permission")
def admin(): pass
gate(action)
def shadow(protect):
    @protect
    def fake(): pass
    authorize(action)
""")
    declarations = signals(result, "security.authorization_declaration")
    assert len(declarations) == 2
    assert all(
        row["context"]["category"] == "mechanism" and row["context"]["integration_only"]
        for row in declarations
    )
    gates = signals(result, "security.access_gate_call_hint")
    assert len(gates) == 2
    assert all(
        row["context"]["category"] == "name_hint" and row["confidence"] == "low" for row in gates
    )
    assert "private-permission" not in json.dumps(result)


@pytest.mark.parametrize(
    "kwargs", [{"node_limit": 0}, {"signal_limit": -1}, {"signal_limit": True}]
)
def test_invalid_work_limits_fail_closed(kwargs):
    with pytest.raises(ValueError):
        scan("pass", **kwargs)
