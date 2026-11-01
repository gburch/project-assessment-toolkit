"""Source controls keep syntax evidence distinct from inferred guarantees."""

import json
from copy import deepcopy

import pytest

from project_assess import javascript_analysis as javascript
from project_assess import js_controls

pytestmark = pytest.mark.skipif(
    not javascript.javascript_analyzer_identity()["available"],
    reason="Optional analysis extra unavailable",
)


def inventory(source, path="src/app.ts"):
    return javascript.analyze_javascript(path, source)["controls"]


def test_shared_typescript_controls_reuse_one_parse_and_do_not_retain_payload(monkeypatch):
    original, calls = javascript._parser, []

    def parser(path):
        calls.append(path)
        return original(path)

    monkeypatch.setattr(javascript, "_parser", parser)
    source = """import { spawn as launch } from "node:child_process";
import { readFile as read } from "node:fs/promises";
import * as crypto from "node:crypto";
interface Extension { run(): void }
class Service { constructor(private adapter: Extension) {} }
async function run(items: string[]) {
  try { for (const item of items) { await read(item); await fetch(item, {signal: controller.signal}); } }
  catch (err) { console.error(err); }
  launch("very-private-command", [], {shell: true});
  crypto.timingSafeEqual(left, right);
  await Promise.all(items.map(load));
  setTimeout(run, 100);
  registry.register(adapter);
  app.get("/healthz", handler);
  cache.get(key);
}
"""
    result = inventory(source)
    by_kind = {row["kind"]: row for row in result["signals"]}
    assert calls == ["src/app.ts"]
    assert set(result["dimensions"]) == {"security", "operability", "extensibility", "performance"}
    assert set(by_kind) >= {
        "shell_execution",
        "constant_time_comparison",
        "interface_declaration",
        "constructor_parameters",
        "io_in_loop",
        "exception_handler",
        "diagnostic_logging",
        "promise_batch",
        "timer_schedule",
        "resource_bound_configuration",
        "health_route_hint",
    }
    shell = by_kind["shell_execution"]
    assert shell["context"]["callee"] == "child_process.spawn"
    assert shell["context"]["resolution"] == "import_binding"
    assert shell["context"]["shell_option"] is True
    assert shell["locations"][0]["line"] == 9
    assert shell["context"]["owner"] == "run"
    assert by_kind["registration_call_hint"]["confidence"] == "hint"
    assert all(row["limitations"] for row in result["signals"])
    assert "very-private-command" not in json.dumps(result)
    assert result["coverage"]["signals_omitted"] == 0


@pytest.mark.parametrize(
    "source",
    [
        """import {spawn as launch} from "node:child_process";
function run(launch, eval, fetch, Promise, console) {
 launch("secret",[],{shell:true}); eval("secret");
 for (const item of items) fetch(item); Promise.all([]); console.log("secret");
}""",
        """import {spawn as launch} from "my-own-module";
import fetch from "my-own-module";
launch("secret",[],{shell:true}); for (let x of xs) fetch(x);""",
        """// eval(secret); require("node:child_process").exec(secret);
const description = "fetch(secret); console.error(secret);";""",
        """const eval = (value) => value;
const Function = factory; eval(secret); new Function(secret);""",
        """import * as cp from "node:child_process";
cp.exec = fake; cp.exec(secret);""",
        """function run(require) { const cp=require("node:child_process"); cp.exec(secret); }""",
    ],
)
def test_comments_strings_unknown_imports_and_shadowed_apis_do_not_become_controls(source):
    assert inventory(source, "src/app.js")["signals"] == []


def test_require_import_binding_stays_in_its_actual_scope():
    source = """function one() {
 const {spawn: launch}=require("node:child_process");
 launch(secret, [], {shell:true});
}
function two() { launch(secret, [], {shell:true}); }
"""
    signals = inventory(source, "src/app.js")["signals"]
    assert [(row["kind"], row["locations"][0]["line"]) for row in signals] == [
        ("shell_execution", 3)
    ]


def test_local_member_names_remain_hints_and_keep_query_shape_context():
    source = """function run(db, registry, logger) {
 db.query(`SELECT ${privateValue}`);
 registry.register(adapter);
 logger.error(privateValue);
}"""
    signals = inventory(source)["signals"]
    assert {row["kind"] for row in signals} == {
        "interpolated_query_argument",
        "registration_call_hint",
        "diagnostic_logging",
    }
    assert all(row["confidence"] == "hint" for row in signals)
    assert all(row["context"]["category"] == "name_hint" for row in signals)
    assert all(row["context"]["resolution"] == "local_member" for row in signals)
    assert "privateValue" not in json.dumps(signals)


def test_loop_context_stops_at_a_nested_callable():
    result = inventory(
        """for (const item of items) {
 const deferred = () => fetch(item);
 await fetch(item);
}""",
        "src/app.js",
    )
    io = [row for row in result["signals"] if row["kind"] == "io_in_loop"]
    assert len(io) == 1 and io[0]["locations"][0]["line"] == 3


def test_signal_limit_preserves_varied_rules_and_reports_omissions():
    result = inventory(
        "\n".join("eval(value);" for _ in range(100))
        + "\ninterface Extension { run(): void }\nconsole.error(error);\nfor(const item of items) fetch(item);"
    )
    assert len(result["signals"]) == js_controls.MAX_SIGNALS
    assert result["coverage"]["signals_total"] == 103
    assert result["coverage"]["signals_omitted"] == 39
    assert {dim for row in result["signals"] for dim in row["dimensions"]} == set(
        result["dimensions"]
    )
    assert result["status"] == "partial"


def test_node_limit_is_separate_from_rich_function_sampling(monkeypatch):
    monkeypatch.setattr(javascript, "MAX_NODES", 16)
    result = inventory("function run() { console.error(error); " + "eval(value);" * 50 + "}")
    assert result["status"] == "partial"
    assert result["coverage"]["nodes_examined"] == 16
    assert result["coverage"]["node_limit"] == 16
    assert all(row["confidence"] == "hint" for row in result["signals"])


def test_all_module_controls_survive_the_rich_file_limit():
    base = javascript.analyze_javascript("src/a.js", "function noop() {}")
    records = []
    for index in range(1000):
        row = deepcopy(base)
        row["path"] = f"src/area{index:04d}/a.js"
        records.append(row)
    late = javascript.analyze_javascript("src/zzzz/late.js", "eval(value);")
    records.append(late)
    result = javascript.summarize_javascript(records)
    late_module = next(row for row in result["modules"] if row["path"] == late["path"])
    assert result["coverage"]["overview_files"] == 1001
    assert result["coverage"]["control_files"] == 1001
    assert result["coverage"]["detail_files"] == 1000
    assert not late_module["detail_selected"]
    assert late_module["control_coverage"]["signals_total"] == 1
    assert late["controls"]["signals"][0]["kind"] == "dynamic_code_execution"
    assert "signals" not in late_module["control_coverage"]


def test_unavailable_parser_does_not_look_like_a_clean_control_scan(monkeypatch):
    monkeypatch.setattr(
        javascript,
        "javascript_analyzer_identity",
        lambda: {
            "available": False,
            "unavailable_reason": "missing_dependencies",
        },
    )
    result = javascript.analyze_javascript("src/app.js", "eval(value);")["controls"]
    assert result["status"] == "unavailable"
    assert result["coverage"]["nodes_examined"] == 0
    assert result["signals"] == [] and result["gaps"]


def test_deep_scope_and_large_option_objects_stay_explicitly_partial():
    deep = "function run(eval) {" + "if (condition) {" * 70 + "eval(secret);" + "}" * 71
    result = inventory(deep, "src/app.js")
    assert result["status"] == "partial"
    assert result["coverage"]["scope_omissions"] == 1
    assert not result["signals"]
    pairs = ",".join(f"key{i}: 0" for i in range(70))
    result = inventory(
        'import {spawn} from "node:child_process"; spawn(cmd, [], {' + pairs + ",shell:true});"
    )
    assert result["status"] == "partial"
    assert result["coverage"]["partial_option_calls"] == 1
    signal = result["signals"][0]
    assert signal["kind"] == "process_execution"
    assert signal["context"]["shell_option"] == "unresolved_options"


def test_process_option_variants_survive_a_same_kind_flood():
    source = 'import {spawn} from "node:child_process";\n'
    source += "\n".join("spawn(command, [], {shell:false});" for _ in range(100))
    source += "\nspawn(command, [], {shell:setting});\nspawn(command, [], {shell:true});"
    result = inventory(source)
    process = [row for row in result["signals"] if row["kind"] == "process_execution"]
    shell = [row for row in result["signals"] if row["kind"] == "shell_execution"]
    assert {row["context"]["shell_option"] for row in process} == {False, "dynamic"}
    assert len(shell) == 1 and shell[0]["context"]["shell_option"] is True
    assert result["coverage"]["signals_total"] == 102
    assert result["coverage"]["signals_retained"] == 64
    assert result["coverage"]["signals_omitted"] == 38


def test_disabled_tls_and_nonpositive_resource_settings_remain_visible():
    source = 'import * as https from "node:https";\n'
    source += "\n".join(
        "fetch(url, {timeout:30}); https.get(url, {rejectUnauthorized:true});" for _ in range(100)
    )
    source += "\nfetch(url, {timeout:0}); https.get(url, {rejectUnauthorized:false});"
    result = inventory(source)
    resources = [row for row in result["signals"] if row["kind"] == "resource_bound_configuration"]
    assert {row["context"]["options"]["timeout"] for row in resources} == {30, 0}
    disabled = [row for row in result["signals"] if row["kind"] == "tls_verification_disabled"]
    assert len(disabled) == 1
    assert disabled[0]["context"]["category"] == "risk_candidate"
    assert result["coverage"]["signals_total"] == 102
    assert result["coverage"]["signals_omitted"] == 38


def test_loop_setup_is_once_only_but_body_condition_and_increment_can_repeat():
    source = """import {readdir, readFile} from "node:fs/promises";
for (const entry of await readdir(root)) {
  await readFile(entry);
}
for (await fetch(setup); await fetch(condition); await fetch(increment)) {
  await fetch(body);
}
while (await fetch(whileCondition)) { await fetch(whileBody); }
do { await fetch(doBody); } while (await fetch(doCondition));
"""
    result = inventory(source, "src/app.mjs")
    io = [row for row in result["signals"] if row["kind"] == "io_in_loop"]
    assert {row["context"]["callee"] for row in io} == {"fs/promises.readFile", "fetch"}
    assert len(io) == 8
    assert not any(row["locations"][0]["line"] == 2 for row in io)
    assert sum(row["locations"][0]["line"] == 5 for row in io) == 2
    assert all(row["context"]["in_loop"] for row in io)


def test_nested_loop_iterable_and_initializer_can_repeat_in_an_outer_body():
    source = """for (const outer of values) {
  for (const inner of await fetch(items)) { consume(inner); }
  for (await fetch(setup); condition; increment) { consume(); }
  const deferred = () => { for (const item of fetch(later)) consume(item); };
}
"""
    result = inventory(source, "src/app.mjs")
    io = [row for row in result["signals"] if row["kind"] == "io_in_loop"]
    assert [row["locations"][0]["line"] for row in io] == [2, 3]


def test_once_only_timer_setup_context_is_not_marked_repeated():
    result = inventory(
        "for (let item = setTimeout(callback, 20); condition; item++) {}", "src/app.js"
    )
    timers = [row for row in result["signals"] if row["kind"] == "timer_schedule"]
    assert len(timers) == 1
    assert not timers[0]["context"]["in_loop"]
