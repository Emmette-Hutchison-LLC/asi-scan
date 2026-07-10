from __future__ import annotations

import asyncio

import typer

import asi_scan.probes  # noqa: F401  (importing registers all probes)
from asi_scan.engine import scan
from asi_scan.models import VerdictStatus
from asi_scan.report import to_json, to_markdown, to_sarif
from asi_scan.selftest import build_vulnerable_server
from asi_scan.target import InMemoryTarget

app = typer.Typer(help="Runtime security scanner for agentic AI systems (OWASP ASI01-ASI10).")

_RENDER = {"json": to_json, "sarif": to_sarif, "md": to_markdown}


@app.callback()
def _main() -> None:
    """asi-scan — runtime OWASP-ASI scanner for agentic AI systems."""


@app.command("scan")
def scan_cmd(
    target: str = typer.Option("self-test", "--target", help="'self-test' or an MCP endpoint URL."),
    asi: str | None = typer.Option(None, "--asi", help="Filter to one ASI id, e.g. ASI02."),
    fmt: str = typer.Option("json", "--format", help="json | sarif | md"),
    authorize: bool = typer.Option(False, "--authorize", help="Attest you are authorized to test this target."),
) -> None:
    """Scan an MCP target and print an ASI-mapped report."""
    if target != "self-test" and not authorize:
        typer.echo("Refusing to scan a non-self-test target without --authorize (you must be authorized).")
        raise typer.Exit(code=2)

    if target == "self-test":
        t = InMemoryTarget(build_vulnerable_server(hardened=False))
    else:  # pragma: no cover - real transport lands in Phase 5
        typer.echo("Remote MCP targets are not yet supported in v0.1.")
        raise typer.Exit(code=2)

    report = asyncio.run(scan(t, asi=asi))
    typer.echo(_RENDER[fmt](report))
    vulnerable = any(f.verdict.status is VerdictStatus.VULNERABLE for f in report.findings)
    raise typer.Exit(code=1 if vulnerable else 0)
