"""Command-line interface for BAIT."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer
import uvicorn

from bait_edr.agent import BAITAgent
from bait_edr.api import create_app
from bait_edr.config import default_rules_path, load_settings
from bait_edr.detection.rules import load_rules
from bait_edr.models import EndpointEvent

app = typer.Typer(help="BAIT endpoint detection and response framework")


def _configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@app.command("validate-rules")
def validate_rules(
    rules: Path | None = typer.Option(
        None,
        exists=True,
        readable=True,
        help="Rule file to validate. Defaults to the rules installed with BAIT.",
    ),
) -> None:
    target = rules or Path(default_rules_path())
    loaded = load_rules(target)
    typer.echo(f"Validated {len(loaded)} rules from {target}")
    for rule in loaded:
        typer.echo(f"  {rule.id}: {rule.title}")


@app.command()
def run(
    config: Path = typer.Option(Path("config.yml")),
    once: bool = typer.Option(False, help="Run one collection cycle and exit"),
) -> None:
    settings = load_settings(config)
    _configure_logging(settings.agent.log_level)
    agent = BAITAgent(settings)
    if once:
        events, alerts = agent.run_once()
        typer.echo(json.dumps({"events": events, "alerts": alerts}, indent=2))
        return
    agent.run_forever()


@app.command()
def serve(
    config: Path = typer.Option(Path("config.yml")),
    host: str | None = typer.Option(None),
    port: int | None = typer.Option(None),
) -> None:
    settings = load_settings(config)
    _configure_logging(settings.agent.log_level)
    uvicorn.run(
        create_app(settings),
        host=host or settings.api.bind_host,
        port=port or settings.api.bind_port,
    )


@app.command()
def demo(config: Path = typer.Option(Path("config.yml"))) -> None:
    """Run safe synthetic events through the real detection engine."""

    settings = load_settings(config)
    agent = BAITAgent(settings, collectors=[])
    samples = [
        EndpointEvent(
            category="process",
            action="start",
            outcome="success",
            process={
                "pid": 4242,
                "ppid": 101,
                "name": "powershell.exe",
                "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "command_line": "powershell.exe -NoProfile -EncodedCommand TEST_ONLY",
                "parent_name": "explorer.exe",
            },
            metadata={"simulation": True},
        ),
        EndpointEvent(
            category="network",
            action="connection",
            outcome="success",
            process={"pid": 4242, "name": "unknown-demo.exe"},
            network={
                "direction": "outbound",
                "protocol": "tcp",
                "remote_ip": "192.0.2.10",
                "remote_port": 4444,
            },
            metadata={"simulation": True},
        ),
    ]
    total = 0
    for event in samples:
        alerts = agent.process_event(event)
        total += len(alerts)
        for alert in alerts:
            typer.echo(alert.model_dump_json(indent=2))
    typer.echo(f"Synthetic demo completed with {total} alert(s)")


if __name__ == "__main__":
    app()
