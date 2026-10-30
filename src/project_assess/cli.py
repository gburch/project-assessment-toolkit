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
    result = argparse.ArgumentParser(prog="pat", description="PAT — Project Assessment Toolkit")
    result.add_argument("--state-dir", help="Local state outside assessed projects")
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("skills", help="Locate the bundled general assessment skills")
    scan = commands.add_parser("scan", help="Capture deterministic source facts")
    scan.add_argument("root")
    scan.add_argument(
        "--report",
        action="append",
        default=[],
        help="Import bounded JUnit, coverage, test-value or Ruff JSON evidence",
    )
    commands.add_parser("list")
    commands.add_parser("rubric")
    for name in ("report", "evidence", "review-template", "review", "doctor", "evolve"):
        command = commands.add_parser(name)
        command.add_argument("assessment_id")
        if name == "report":
            command.add_argument("--format", choices=("json", "markdown"), default="json")
        if name == "evidence":
            command.add_argument("--evidence-id")
        if name == "review":
            command.add_argument("--input", required=True)
            command.add_argument("--request-id")
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
            output = service.scan(args.root, args.report)
        elif args.command == "list":
            output = service.list_projects()
        elif args.command == "rubric":
            output = service.rubric()
        elif args.command == "doctor":
            output = service.doctor(args.assessment_id)
        elif args.command == "evolve":
            output = service.evolve(args.assessment_id)
        elif args.command == "badge":
            output = service.get_badge(args.assessment_id, args.dimension, format=args.format)
            if args.format == "svg":
                print(output)
                return 0
        elif args.command == "report":
            output = service.get_report(args.assessment_id)
            if args.format == "markdown":
                print(markdown_report(output))
                return 0
        elif args.command == "evidence":
            output = service.evidence(args.assessment_id, args.evidence_id)
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
