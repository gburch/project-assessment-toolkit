"""Local command interface; never execute code from an assessed project."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .rubric import DIMENSIONS


def _input(path):
    source = Path(path)
    if source.stat().st_size > 2 * 1024 * 1024:
        raise ValueError("Input document exceeds 2 MiB")
    return json.loads(source.read_text())


def parser():
    from .analyzer_registry import registered_analyzer_names

    result = argparse.ArgumentParser(prog="pat", description="PAT — Project Assessment Toolkit")
    result.add_argument("--state-dir", help="Local state outside assessed projects")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("skills", help="Locate the bundled general assessment skills")
    commands.add_parser("info", help="Read this installation's tool and instruction provenance")
    commands.add_parser("analyzers", help="List trusted optional analyzers and availability")
    scan = commands.add_parser("scan", help="Capture deterministic source facts")
    scan.add_argument("root")
    scan.add_argument("--brief", action="store_true", help="Return a compact, queryable handoff")
    scan.add_argument(
        "--analysis-profile",
        choices=("standard", "deep"),
        default="standard",
        help="Select recorded collection/work budgets; independent of goal profiles",
    )
    scan.add_argument(
        "--analyzer",
        dest="analyzers",
        action="append",
        choices=registered_analyzer_names(),
        default=[],
        help="Opt into an installed trusted analyzer on captured source",
    )
    scan.add_argument(
        "--report",
        action="append",
        default=[],
        help="Import bounded JUnit, coverage, test-value, Ruff JSON or SARIF 2.1 (.sarif/.sarif.json) evidence",
    )
    commands.add_parser("list")
    commands.add_parser("rubric")
    for name in ("report", "evidence", "review-template", "review", "doctor", "evolve"):
        command = commands.add_parser(name)
        command.add_argument("assessment_id")
        if name == "report":
            command.add_argument("--format", choices=("json", "markdown"), default="json")
            command.add_argument("--brief", action="store_true", help="Read a compact handoff")
        if name == "evidence":
            command.add_argument("--evidence-id")
        if name == "doctor":
            command.add_argument(
                "--limit",
                type=int,
                default=100,
                help="Share 1..100 candidates across evidence families; 20 is useful for a first pass",
            )
        if name == "review":
            command.add_argument("--input", required=True)
            command.add_argument("--request-id")
    query = commands.add_parser("evidence-query", help="Browse bounded captured evidence")
    query.add_argument("assessment_id")
    query.add_argument(
        "--view",
        choices=(
            "index",
            "details",
            "candidates",
            "snippets",
            "graph",
            "hotspots",
            "coverage",
            "provenance",
        ),
        default="index",
    )
    for field, help_text in (
        ("kind", "Evidence kind, such as python, static-analysis or javascript-analysis"),
        ("path", "Case-sensitive substring of a captured relative path"),
        ("role", "Captured/heuristic role: production, test, tooling or unknown"),
        ("candidate-kind", "Static candidate kind, such as complex_function"),
    ):
        query.add_argument("--" + field, help=help_text)
    query.add_argument("--line", type=int)
    query.add_argument("--offset", type=int, default=0)
    query.add_argument("--limit", type=int, default=20)
    query.add_argument("--max-chars", type=int, default=24000)
    context = commands.add_parser(
        "source-context", help="Read captured source only when its live digest still matches"
    )
    context.add_argument("assessment_id")
    context.add_argument("evidence_id")
    context.add_argument("--line", type=int, default=1)
    context.add_argument("--end-line", type=int)
    context.add_argument("--max-chars", type=int, default=8000)
    badge = commands.add_parser(
        "badge", help="Export a public GitHub badge from a saved assessment"
    )
    badge.add_argument("assessment_id")
    badge.add_argument("--dimension", choices=("summary", *DIMENSIONS), default="summary")
    badge.add_argument("--format", choices=("svg", "json"), default="svg")
    targets = commands.add_parser("targets")
    targets.add_argument("project_id")
    choice = targets.add_mutually_exclusive_group(required=True)
    choice.add_argument("--profile")
    choice.add_argument("--input")
    targets.add_argument("--expected-revision", type=int, required=True)
    targets.add_argument("--request-id")
    for name in ("progress", "history"):
        commands.add_parser(name).add_argument("project_id")
    server = commands.add_parser("serve", help="Serve the local interactive report")
    server.add_argument("--port", type=int, default=0)
    server.add_argument("--open", action="store_true", help="Open the browser")
    mcp = commands.add_parser("mcp", help="Run a local stdio MCP adapter")
    mcp.add_argument("--allowed-root", required=True, action="append")
    return result


def main(argv=None):
    argument_parser = parser()
    args = argument_parser.parse_args(argv)
    if args.command == "analyzers":
        from .analyzer_registry import list_analyzers

        print(json.dumps(list_analyzers(), indent=2, allow_nan=False))
        return 0
    if args.command == "info":
        from .provenance import tool_info

        print(json.dumps(tool_info(), indent=2, allow_nan=False))
        return 0
    if args.command == "skills":
        from importlib.resources import files

        directory = Path(str(files("project_assess").joinpath(".agents", "skills")))
        if not directory.is_dir():
            directory = Path(__file__).resolve().parents[2] / ".agents" / "skills"
        print(
            json.dumps(
                [
                    {"name": path.name, "path": str(path / "SKILL.md")}
                    for path in sorted(directory.iterdir())
                    if path.is_dir() and (path / "SKILL.md").is_file()
                ],
                indent=2,
            )
        )
        return 0
    if not args.state_dir:
        argument_parser.error("--state-dir is required for assessment commands")
    try:
        from .service import AssessmentService, markdown_report

        if args.command == "scan" and Path(args.state_dir).expanduser().resolve().is_relative_to(
            Path(args.root).expanduser().resolve()
        ):
            raise ValueError("State directory must be outside assessed projects")
        service = AssessmentService(args.state_dir, getattr(args, "allowed_root", None))
        if args.command == "mcp":
            from .mcp_server import run

            run(service)
            return 0
        if args.command == "serve":
            from .web import serve

            serve(service, args.port, open_browser=args.open)
            return 0
        if args.command == "scan":
            output = service.scan(
                args.root,
                args.report,
                analysis_profile=args.analysis_profile,
                analyzers=args.analyzers,
            )
            if args.brief:
                output = service.overview(output["id"])
        elif args.command == "list":
            output = service.list_projects()
        elif args.command == "rubric":
            output = service.rubric()
        elif args.command == "doctor":
            output = service.doctor(args.assessment_id, limit=args.limit)
        elif args.command == "evolve":
            output = service.evolve(args.assessment_id)
        elif args.command == "badge":
            output = service.get_badge(args.assessment_id, args.dimension, format=args.format)
            if args.format == "svg":
                print(output)
                return 0
        elif args.command == "report":
            if args.brief and args.format != "json":
                raise ValueError("--brief requires --format json")
            output = (
                service.overview(args.assessment_id)
                if args.brief
                else service.get_report(args.assessment_id)
            )
            if args.format == "markdown":
                print(markdown_report(output))
                return 0
        elif args.command == "evidence":
            output = service.evidence(args.assessment_id, args.evidence_id)
        elif args.command == "evidence-query":
            output = service.query_evidence(
                args.assessment_id,
                **{
                    key: getattr(args, key)
                    for key in (
                        "view",
                        "kind",
                        "path",
                        "role",
                        "candidate_kind",
                        "line",
                        "offset",
                        "limit",
                        "max_chars",
                    )
                },
            )
        elif args.command == "source-context":
            output = service.source_context(
                args.assessment_id,
                args.evidence_id,
                line=args.line,
                end_line=args.end_line,
                max_chars=args.max_chars,
            )
        elif args.command == "review-template":
            output = service.review_template(args.assessment_id)
        elif args.command == "review":
            output = service.submit_review(args.assessment_id, _input(args.input), args.request_id)
        elif args.command == "targets":
            output = service.set_targets(
                args.project_id,
                _input(args.input) if args.input else None,
                args.expected_revision,
                args.profile,
                args.request_id,
            )
        elif args.command == "history":
            output = service.history(args.project_id)
        else:
            output = service.progress(args.project_id)
        print(json.dumps(output, indent=2, allow_nan=False))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"pat: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
