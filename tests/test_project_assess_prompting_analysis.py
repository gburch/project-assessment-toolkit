"""Prompting hints remain source-bound and separate from reliance judgments."""

import ast
import hashlib
import json

import pytest

from project_assess import prompting_analysis as analysis
from project_assess.javascript_analysis import javascript_analyzer_identity


def source(path, text, role="production"):
    return {
        "path": path,
        "text": text,
        "role": role,
        "evidence_id": "e-" + path,
        "digest": "sha256:" + hashlib.sha256(text.encode()).hexdigest(),
    }


def counts(result):
    return result["summary"]["counts_by_kind"]


@pytest.mark.parametrize("validator", ["Draft7Validator", "Draft202012Validator"])
def test_validator_without_model_use_is_not_an_output_contract(validator):
    result = analysis.analyze_prompting(
        [
            source(
                "app.py",
                f"from jsonschema import {validator}\nerrors = {validator}({{}}).iter_errors(value)\n",
            )
        ]
    )
    assert counts(result)["output_contract"] == 0
    assert result["coverage"]["schema_validation_without_model_context"] == 1
    assert counts(result)["model_invocation"] == counts(result)["model_client_setup"] == 0


def test_validator_beside_model_use_is_an_output_contract():
    result = analysis.analyze_prompting(
        [
            source(
                "src/agent/check.py",
                "from jsonschema import validate\nvalidate(reply, schema)\n",
            ),
            source(
                "src/agent/model.py",
                "import anthropic\nclient = anthropic.Anthropic()\n",
            ),
            source(
                "src/billing/rules.py",
                "from jsonschema import validate\nvalidate(invoice, schema)\n",
            ),
        ]
    )
    assert counts(result)["output_contract"] == 1
    assert [row["path"] for row in result["signals"] if row["kind"] == "output_contract"] == [
        "src/agent/check.py"
    ]
    assert result["coverage"]["schema_validation_without_model_context"] == 1
    checked = next(
        row for row in result["coverage"]["files"] if row["path"] == "src/agent/check.py"
    )
    assert checked["signal_counts"] == {"output_contract": 1}


def test_validator_in_a_sibling_package_directory_is_an_output_contract():
    result = analysis.analyze_prompting(
        [
            source(
                "src/pkg/schemas/output.py", "from jsonschema import validate\nvalidate(a, b)\n"
            ),
            source("src/pkg/llm/model.py", "import anthropic\nclient = anthropic.Anthropic()\n"),
        ]
    )
    assert counts(result)["output_contract"] == 1
    assert result["coverage"]["schema_validation_without_model_context"] == 0


def test_guidance_can_be_development_or_product_instruction_without_runtime_grade():
    records = [
        source("AGENTS.md", "Use deterministic tests.\n", "tooling"),
        source(".agents/skills/review/SKILL.md", "Review the code.\n", "tooling"),
        source("README.md", "```python\nclient.responses.create(prompt=example)\n```\n"),
        source("src/app.py", "def add(a, b):\n    return a + b\n"),
    ]
    result = analysis.analyze_prompting(records)
    assert result["status"] == "complete"
    assert counts(result)["development_guidance"] == 2
    assert counts(result)["runtime_prompt_asset"] == counts(result)["model_invocation"] == 0
    assert all(
        row["context"]["consumption"].endswith("scope_unverified") for row in result["signals"]
    )
    assert "level" not in result and "ratio" not in result
    assert "AI authorship" in result["caveat"]


@pytest.mark.parametrize(
    "text",
    [
        "from openai import OpenAI\nclient = OpenAI()\nclient.responses.create(input='PRIVATE_PROMPT_SENTINEL')\n",
        "import openai as sdk\nclient = sdk.AsyncOpenAI()\nclient.chat.completions.create(messages=[])\n",
        "from anthropic import Anthropic as Model\nclient = Model()\nclient.messages.create(messages=[])\n",
        "import boto3\nclient = boto3.client('bedrock-runtime')\nclient.converse(messages=[])\n",
        "from langchain_openai import ChatOpenAI\nmodel = ChatOpenAI()\nmodel.invoke('PRIVATE_PROMPT_SENTINEL')\n",
    ],
)
def test_import_bound_model_clients_and_generation_calls_are_distinct(text):
    record = source("src/app.py", text)
    result = analysis.analyze_prompting([record])
    assert counts(result)["model_client_setup"] == counts(result)["model_invocation"] == 1
    assert result["summary"]["model_call_files"] == 1
    assert "PRIVATE_PROMPT_SENTINEL" not in json.dumps(result)
    for row in result["signals"]:
        assert row["source_evidence_id"] == record["evidence_id"]
        assert row["digest"] == record["digest"]
        assert 1 <= row["line"] <= len(text.splitlines())


def test_optional_model_assistance_does_not_infer_product_prevalence_or_score():
    record = source(
        "src/help.py",
        "from litellm import completion as suggest\ndef optional_help():\n    return suggest(messages=[])\n",
    )
    result = analysis.analyze_prompting([record])
    assert counts(result)["model_invocation"] == 1
    assert "level" not in result and "confidence" not in result
    assert "prompting percentage" in result["caveat"]


def test_hybrid_contract_and_sampling_syntax_never_establish_repeatability():
    record = source(
        "src/hybrid.py",
        "from openai import OpenAI\nimport jsonschema\nclient = OpenAI()\nanswer = client.responses.create(input=request, response_format=schema, temperature=0, seed=5)\njsonschema.validate(answer, schema)\n",
    )
    result = analysis.analyze_prompting([record])
    assert counts(result)["model_invocation"] == 1
    assert counts(result)["output_contract"] == 3
    sampling = next(
        row
        for row in result["signals"]
        if row["context"].get("mechanism") == "sampling_configuration"
    )
    assert sampling["context"]["repeatability"] == "unestablished"
    assert "observed_variability" not in result


def test_responses_text_format_is_a_contract_option_without_inspecting_its_prompt():
    result = analysis.analyze_prompting(
        [
            source(
                "app.py",
                "from openai import OpenAI\nclient = OpenAI()\nclient.responses.create(input='PRIVATE_PROMPT_SENTINEL', text={'format': schema})\n",
            )
        ]
    )
    assert counts(result)["output_contract"] == 1
    assert "PRIVATE_PROMPT_SENTINEL" not in json.dumps(result)


def test_prompt_led_assets_and_agent_declarations_remain_heuristics():
    records = [
        source("prompts/planner.md", "Choose a plan. PRIVATE_PROMPT_SENTINEL\n"),
        source(
            "src/agent.py",
            "from crewai import Agent\nagent = Agent(role='planner', goal='PRIVATE_PROMPT_SENTINEL')\n",
        ),
        source("promptfooconfig.yaml", "providers: []\ntests: []\n", "test"),
    ]
    result = analysis.analyze_prompting(records)
    assert counts(result)["runtime_prompt_asset"] == 1
    assert counts(result)["agent_orchestration"] == 1
    assert counts(result)["evaluation_signal"] == 1
    assert counts(result)["model_invocation"] == 0
    assert "PRIVATE_PROMPT_SENTINEL" not in json.dumps(result)


@pytest.mark.parametrize(
    "text",
    [
        "# from openai import OpenAI\n# client.responses.create(input=message)\nvalue = 'client.responses.create()'\n",
        "client.responses.create(input=message)\n",
        "from openai import OpenAI\ndef f(OpenAI):\n    client = OpenAI()\n    return client.responses.create(input='x')\n",
        "from openai import OpenAI\nclient = OpenAI()\ndef f(client):\n    return client.responses.create(input='x')\n",
        "from openai import OpenAI\nclient = OpenAI()\nclient = fake\nclient.responses.create(input='x')\n",
        "from openai import OpenAI\nclass Example:\n    client = OpenAI()\n    def f(self):\n        return client.responses.create(input='x')\n",
    ],
)
def test_comments_unbound_names_shadowing_and_reassignments_are_not_invocations(text):
    result = analysis.analyze_prompting([source("src/app.py", text)])
    assert counts(result)["model_invocation"] == 0


def test_self_client_setup_is_visible_without_speculative_attribute_dataflow():
    result = analysis.analyze_prompting(
        [
            source(
                "src/service.py",
                "from openai import OpenAI\nclass Service:\n    def __init__(self):\n        self.client = OpenAI()\n    def ask(self):\n        return self.client.responses.create(input='x')\n",
            )
        ]
    )
    assert counts(result)["model_client_setup"] == 1
    assert counts(result)["model_invocation"] == 0
    assert "Missing signals" in result["caveat"]


@pytest.mark.parametrize(
    "mutation",
    [
        "client.responses.create = fake",
        "client.responses = fake",
        "del client.responses.create",
        "client.responses['create'] = fake",
        "del client.responses['create']",
        "client.responses.create += fake",
        "def patch():\n    client.responses.create = fake",
    ],
)
def test_mutated_python_sdk_receivers_do_not_retain_generation_identity(mutation):
    text = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        f"{mutation}\n"
        "client.responses.create(input='not established')\n"
        "other = OpenAI()\n"
        "other.responses.create(input='still bound')\n"
    )
    result = analysis.analyze_prompting([source("src/app.py", text)])
    assert counts(result)["model_client_setup"] == 2
    assert counts(result)["model_invocation"] == 1
    invocation = next(row for row in result["signals"] if row["kind"] == "model_invocation")
    assert invocation["line"] == len(text.splitlines())


def test_empty_assets_do_not_create_uncitable_line_one_hints():
    result = analysis.analyze_prompting(
        [source("prompts/empty.prompt", ""), source("AGENTS.md", "")]
    )
    assert result["signals"] == []


def test_analysis_is_deterministic_across_input_order_and_preserves_roles():
    records = [
        source("prompts/help.txt", "Help\n"),
        source("AGENTS.md", "Rules\n", "tooling"),
        source(
            "tests/eval.py",
            "from deepeval import assert_test\nassert_test(case, metrics=[])\n",
            "test",
        ),
    ]
    forward = analysis.analyze_prompting(records)
    assert forward == analysis.analyze_prompting(list(reversed(records)))
    assert counts(forward)["evaluation_signal"] == 1
    assert forward["summary"]["counts_by_role"] == {"production": 1, "test": 1, "tooling": 1}


def test_cached_python_facts_reuse_the_existing_parse_without_changing_evidence(monkeypatch):
    text = (
        "from openai import OpenAI\n"
        "client = OpenAI()\n"
        "client.responses.create(input=request, response_format=schema)\n"
    )
    records = [source("src/app.py", text), source("AGENTS.md", "Guidance\n", "tooling")]
    expected = analysis.analyze_prompting(records)
    facts = analysis.python_prompting_facts(ast.parse(text))

    def unexpected_parse(*args, **kwargs):
        raise AssertionError("Cached Python facts must not parse the source again")

    monkeypatch.setattr(analysis.ast, "parse", unexpected_parse)
    assert analysis.analyze_prompting(records, python_facts={"src/app.py": facts}) == expected
    assert analysis._python(text, tree=ast.Module(body=[], type_ignores=[])) == (
        [],
        "complete",
        None,
    )


def test_missing_cached_python_tree_remains_partial_without_reparsing(monkeypatch):
    def unexpected_parse(*args, **kwargs):
        raise AssertionError("An unavailable existing tree must remain unavailable")

    monkeypatch.setattr(analysis.ast, "parse", unexpected_parse)
    facts = analysis.python_prompting_facts(None)
    assert facts[0] == [] and facts[1] == "partial"
    records = [source("src/broken.py", "from openai import OpenAI\ninvalid(\n")]
    result = analysis.analyze_prompting(records, python_facts={"src/broken.py": facts})
    assert result["status"] == "partial"
    assert result["coverage"]["partial_files"] == 1
    assert result["signals"] == []
    assert analysis._python(records[0]["text"], tree=None) == facts
    assert analysis.analyze_prompting(records, python_facts={"src/broken.py": None}) == result


def test_partial_unsupported_and_deadline_gaps_are_explicit(monkeypatch):
    result = analysis.analyze_prompting(
        [source("src/broken.py", "def invalid(\n"), source("src/App.swift", "func app() {}\n")]
    )
    assert result["status"] == "partial"
    assert result["coverage"]["partial_files"] == result["coverage"]["unsupported_files"] == 1
    monkeypatch.setattr(analysis, "_CLOCK", lambda: 10)
    late = analysis.analyze_prompting(
        [source("src/app.py", "raise RuntimeError('never run')\n")], deadline=9
    )
    assert late["coverage"]["omitted_files"] == 1 and late["signals"] == []


def test_byte_and_signal_bounds_keep_contrasting_categories(monkeypatch):
    monkeypatch.setattr(analysis, "MAX_FILE_BYTES", 20)
    large = analysis.analyze_prompting([source("prompts/large.prompt", "x" * 21)])
    assert large["coverage"]["omitted_files"] == 1
    monkeypatch.setattr(analysis, "MAX_FILE_BYTES", 1000)
    monkeypatch.setattr(analysis, "MAX_SIGNALS", 3)
    records = [source(f"prompts/{index}.md", "Prompt\n") for index in range(12)]
    records += [
        source("AGENTS.md", "Guidance\n", "tooling"),
        source("eval.py", "from ragas import evaluate\nevaluate(dataset)\n", "test"),
    ]
    result = analysis.analyze_prompting(records)
    assert result["summary"]["signal_count"] == 14
    assert {row["kind"] for row in result["signals"]} == {
        "development_guidance",
        "runtime_prompt_asset",
        "evaluation_signal",
    }
    assert result["status"] == "partial"


@pytest.mark.parametrize(
    "path", ["../escape.py", "/absolute.py", ".", "a//b.py", "a\\b.py", "a\x00b.py"]
)
def test_paths_must_be_captured_relative_files(path):
    with pytest.raises(ValueError):
        analysis.analyze_prompting([source(path, "pass\n")])


@pytest.mark.parametrize("deadline", [float("inf"), float("nan"), True, "soon"])
def test_deadline_requires_finite_numeric_time(deadline):
    with pytest.raises(ValueError):
        analysis.analyze_prompting([], deadline=deadline)


def test_duplicate_paths_and_missing_identities_fail_closed():
    record = source("app.py", "pass\n")
    with pytest.raises(ValueError):
        analysis.analyze_prompting([record, record])
    record.pop("evidence_id")
    with pytest.raises(ValueError):
        analysis.analyze_prompting([record])


@pytest.mark.skipif(
    not javascript_analyzer_identity()["available"], reason="Optional JS syntax parser absent"
)
def test_javascript_sdk_bindings_shadowing_and_output_options():
    text = "import OpenAI from 'openai';\nconst client = new OpenAI();\nclient.chat.completions.create({messages: [], response_format: schema, temperature: 0});\nfunction shadow(client) { client.responses.create({input: text}); }\n// client.responses.create({input:'private'});\nconst literal = 'client.responses.create()';\n"
    result = analysis.analyze_prompting([source("src/app.ts", text)])
    assert counts(result)["model_client_setup"] == 1
    assert counts(result)["model_invocation"] == 1
    assert counts(result)["output_contract"] == 2


@pytest.mark.skipif(
    not javascript_analyzer_identity()["available"], reason="Optional JS syntax parser absent"
)
def test_javascript_function_sdk_imports_and_agent_constructor():
    records = [
        source(
            "src/app.ts",
            "import { generateText as answer } from 'ai';\nimport { Agent } from '@openai/agents';\nconst agent = new Agent({instructions: 'PRIVATE_PROMPT_SENTINEL'});\nanswer({prompt: request});\n",
        )
    ]
    result = analysis.analyze_prompting(records)
    assert counts(result)["model_invocation"] == counts(result)["agent_orchestration"] == 1
    assert "PRIVATE_PROMPT_SENTINEL" not in json.dumps(result)


@pytest.mark.skipif(
    not javascript_analyzer_identity()["available"], reason="Optional JS syntax parser absent"
)
@pytest.mark.parametrize(
    "shadowed",
    [
        "function outer() { function generateText() {} generateText({}); }",
        "function outer() { function* generateText() {} generateText({}); }",
        "{ class generateText {} generateText({}); }",
        "try {} catch (generateText) { generateText({}); }",
        "const local = function generateText() { generateText({}); };",
        "const local = class generateText { run() { generateText({}); } };",
    ],
)
def test_javascript_declaration_and_catch_shadows_preserve_unshadowed_import(shadowed):
    text = f"import {{ generateText }} from 'ai';\n{shadowed}\ngenerateText({{}});\n"
    result = analysis.analyze_prompting([source("src/app.ts", text)])
    assert result["status"] == "complete"
    assert counts(result)["model_invocation"] == 1
    invocation = next(row for row in result["signals"] if row["kind"] == "model_invocation")
    assert invocation["line"] == 3


@pytest.mark.skipif(
    not javascript_analyzer_identity()["available"], reason="Optional JS syntax parser absent"
)
def test_javascript_var_shadow_escapes_block_but_lexical_shadow_does_not():
    text = (
        "import { generateText } from 'ai';\n"
        "function shadow() { { var generateText = fake; } generateText({}); }\n"
        "function valid() { { let generateText = fake; generateText({}); } generateText({}); }\n"
        "generateText({});\n"
    )
    result = analysis.analyze_prompting([source("src/app.ts", text)])
    assert counts(result)["model_invocation"] == 2
    assert sorted(
        row["line"] for row in result["signals"] if row["kind"] == "model_invocation"
    ) == [3, 4]


@pytest.mark.skipif(
    not javascript_analyzer_identity()["available"], reason="Optional JS syntax parser absent"
)
def test_commonjs_sdk_use_is_explicitly_unresolved_instead_of_clean_empty():
    result = analysis.analyze_prompting(
        [
            source(
                "app.cjs",
                "const OpenAI = require('openai');\nconst client = new OpenAI();\nclient.responses.create({input: 'PRIVATE_PROMPT_SENTINEL'});\n",
            )
        ]
    )
    assert result["status"] == "partial"
    assert counts(result)["model_invocation"] == 0
    assert any("CommonJS" in gap for gap in result["gaps"])
    assert "PRIVATE_PROMPT_SENTINEL" not in json.dumps(result)


@pytest.mark.skipif(
    not javascript_analyzer_identity()["available"], reason="Optional JS syntax parser absent"
)
def test_javascript_responses_text_format_option():
    result = analysis.analyze_prompting(
        [
            source(
                "app.ts",
                "import OpenAI from 'openai';\nconst client = new OpenAI();\nclient.responses.create({input: request, text: {format: schema}});\n",
            )
        ]
    )
    assert counts(result)["model_invocation"] == counts(result)["output_contract"] == 1
