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
    commands.add_parser(
        "analyzers", help="List trusted analyzers, availability and default profiles"
    )
    scan = commands.add_parser("scan", help="Capture deterministic source facts")
    scan.add_argument("root")
    scan.add_argument("--brief", action="store_true", help="Return a compact, queryable handoff")
    scan.add_argument(
        "--analysis-profile",
        choices=("standard", "deep"),
        default="standard",
        help="Deep includes dead-code and documentation drift review inputs and requests configured trusted analyzers; independent of goals",
    )
    scan.add_argument(
        "--analyzer",
        dest="analyzers",
        action="append",
        choices=registered_analyzer_names(),
        default=[],
        help="Include an installed trusted analyzer; Deep already requests Vulture and Joern",
    )
    scan.add_argument(
        "--role-overrides",
        help="JSON path-role rules kept outside the assessed repository",
    )
    scan.add_argument(
        "--display-name", help="Report name; defaults to the origin repository or directory name"
    )
    scan.add_argument(
        "--report",
        action="append",
        default=[],
        help="Import bounded JUnit, coverage, test-value, observation, burden-context, Ruff JSON or SARIF evidence",
    )
    backfill = commands.add_parser(
        "backfill",
        help="Capture facts-only snapshots of earlier commits from local Git objects",
    )
    backfill.add_argument("root")
    selection = backfill.add_mutually_exclusive_group(required=True)
    selection.add_argument(
        "--months", type=int, help="Month-end first-parent commits for the last N months (1..12)"
    )
    selection.add_argument("--tags", type=int, help="The newest N tags (1..12)")
    selection.add_argument(
        "--revision",
        dest="revisions",
        action="append",
        help="An explicit commit, tag or branch name; repeat for up to 12",
    )
    backfill.add_argument("--analysis-profile", choices=("standard", "deep"), default="standard")
    delta = commands.add_parser(
        "ci-delta", help="Compare saved native leads; advisory unless explicit kinds are selected"
    )
    delta.add_argument("before_id")
    delta.add_argument("after_id")
    delta.add_argument("--format", choices=("json", "markdown"), default="markdown")
    delta.add_argument("--fail-on-kind", action="append", default=[])
    finding = commands.add_parser("finding-status", help="Read source-bound finding decisions")
    finding.add_argument("assessment_id")
    decision = commands.add_parser(
        "finding-event", help="Append an explicit finding decision or verification"
    )
    decision.add_argument("origin_assessment_id")
    decision.add_argument("--origin-review-id")
    decision.add_argument("--input", required=True)
    decision.add_argument("--expected-event-id")
    decision.add_argument("--request-id")
    commands.add_parser("list")
    commands.add_parser("rubric")
    commands.add_parser("review-schema", help="Read the review contract, with all optional fields")
    setup = commands.add_parser(
        "setup-joern", help="Download the pinned Joern release and verify its SHA-256"
    )
    setup.add_argument("destination", help="Directory outside assessed projects")
    for name in (
        "report",
        "export-report",
        "evidence",
        "review-template",
        "challenge-template",
        "review",
        "doctor",
        "evolve",
    ):
        command = commands.add_parser(name)
        command.add_argument("assessment_id")
        if name == "report":
            command.add_argument("--format", choices=("json", "markdown"), default="json")
            command.add_argument("--brief", action="store_true", help="Read a compact handoff")
            command.add_argument("--section", help="Read one section a brief handoff omitted")
        if name == "evidence":
            command.add_argument("--evidence-id")
        if name == "doctor":
            command.add_argument(
                "--limit",
                type=int,
                default=100,
                help="Share 1..100 candidates across evidence families; 20 is useful for a first pass",
            )
            command.add_argument(
                "--full", action="store_true", help="Include bodies other commands also supply"
            )
        if name == "review-template":
            command.add_argument("--mode", choices=("fresh", "refresh"))
            command.add_argument(
                "--full", action="store_true", help="Include every optional authored section"
            )
        if name in {"review", "challenge-template"}:
            command.add_argument("--input", required=True)
        if name == "review":
            command.add_argument("--request-id")
            command.add_argument(
                "--check", action="store_true", help="Run every final check without saving"
            )
        if name == "export-report":
            command.add_argument(
                "--include-evidence",
                action="store_true",
                help="Keep evidence bodies in report.json; they can dominate its size",
            )
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
            "dataflow",
            "prompting",
            "hotspots",
            "coverage",
            "provenance",
            "areas",
            "area-dependencies",
            "controls",
            "burden",
            "review-plan",
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
    query.add_argument(
        "--dimension",
        choices=DIMENSIONS,
    )
    query.add_argument("--offset", type=int, default=0)
    query.add_argument("--limit", type=int, default=20)
    query.add_argument("--max-chars", type=int, default=24000)
    context = commands.add_parser(
        "source-context", help="Read captured source only when its live digest still matches"
    )
    context.add_argument("assessment_id")
    context.add_argument("evidence_id", nargs="?")
    context.add_argument("--path", help="Exact captured relative path, instead of an evidence ID")
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
    if args.command == "review-schema":
        from .service import AssessmentService

        print(json.dumps(AssessmentService.review_schema(), indent=2, allow_nan=False))
        return 0
    if args.command == "setup-joern":
        from .joern_setup import setup_joern

        try:
            print(json.dumps(setup_joern(args.destination), indent=2, allow_nan=False))
        except (ValueError, OSError) as exc:
            print(f"pat: {exc}", file=sys.stderr)
            return 2
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
        from .progress import stderr_progress
        from .service import AssessmentService, markdown_report

        if args.command in {"scan", "backfill"} and Path(
            args.state_dir
        ).expanduser().resolve().is_relative_to(Path(args.root).expanduser().resolve()):
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
            if args.role_overrides and (
                Path(args.role_overrides)
                .expanduser()
                .resolve()
                .is_relative_to(Path(args.root).expanduser().resolve())
            ):
                raise ValueError("Role overrides must be kept outside the assessed project")
            with stderr_progress():
                output = service.scan(
                    args.root,
                    args.report,
                    analysis_profile=args.analysis_profile,
                    analyzers=args.analyzers,
                    role_overrides=_input(args.role_overrides) if args.role_overrides else None,
                    display_name=args.display_name,
                )
            if args.brief:
                output = service.overview(output["id"])
        elif args.command == "backfill":
            output = service.backfill(
                args.root,
                months=args.months,
                tags=args.tags,
                revisions=args.revisions,
                analysis_profile=args.analysis_profile,
            )
        elif args.command == "ci-delta":
            from .ci_delta import render_ci_markdown

            output = service.ci_delta(
                args.before_id, args.after_id, fail_on_kinds=args.fail_on_kind
            )
            print(
                render_ci_markdown(output)
                if args.format == "markdown"
                else json.dumps(output, indent=2, allow_nan=False)
            )
            return output["policy"]["exit_code"]
        elif args.command == "finding-status":
            output = service.finding_status(args.assessment_id)
        elif args.command == "finding-event":
            output = service.record_finding(
                args.origin_assessment_id,
                _input(args.input),
                origin_review_id=args.origin_review_id,
                expected_event_id=args.expected_event_id,
                request_id=args.request_id,
            )
        elif args.command == "list":
            output = service.list_projects()
        elif args.command == "rubric":
            output = service.rubric()
        elif args.command == "doctor":
            output = service.doctor(args.assessment_id, limit=args.limit, brief=not args.full)
        elif args.command == "evolve":
            output = service.evolve(args.assessment_id)
        elif args.command == "badge":
            output = service.get_badge(args.assessment_id, args.dimension, format=args.format)
            if args.format == "svg":
                print(output)
                return 0
        elif args.command == "report":
            if (args.brief or args.section) and args.format != "json":
                raise ValueError("--brief and --section require --format json")
            if args.section:
                print(
                    json.dumps(
                        service.overview(args.assessment_id, section=args.section),
                        indent=2,
                        allow_nan=False,
                    )
                )
                return 0
            output = (
                service.overview(args.assessment_id)
                if args.brief
                else service.get_report(args.assessment_id)
            )
            if args.format == "markdown":
                print(markdown_report(output))
                return 0
        elif args.command == "export-report":
            output = service.export_report(
                args.assessment_id, include_evidence=args.include_evidence
            )
            for warning in output["warnings"]:
                print(f"pat: warning: {warning}", file=sys.stderr)
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
                        "dimension",
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
                path=args.path,
            )
        elif args.command == "review-template":
            output = service.review_template(args.assessment_id, mode=args.mode, full=args.full)
        elif args.command == "challenge-template":
            output = service.challenge_template(args.assessment_id, _input(args.input))
        elif args.command == "review" and args.check:
            if args.request_id:
                raise ValueError("--check saves nothing, so it takes no --request-id")
            output = service.check_review(args.assessment_id, _input(args.input))
            print(json.dumps(output, indent=2, allow_nan=False))
            return 0 if output["valid"] else 2
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
