"""CLI for mcpx."""

from __future__ import annotations

import asyncio
import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .banner import MCPX_BANNER
from .probe import probe_server

console = Console()


def _banner() -> None:
    console.print(f"[bold cyan]{MCPX_BANNER}[/bold cyan]")


class BannerGroup(click.Group):
    def get_help(self, ctx: click.Context) -> str:
        _banner()
        return super().get_help(ctx)


def _render_probe(data: dict) -> None:
    server = data.get("fingerprint", {})
    console.print(
        Panel(
            f"Transport:   {server.get('transport')}\n"
            f"Server:      {server.get('name')} {server.get('version')}\n"
            f"Capabilities: tools {'✓' if data.get('tools') else '✗'}  resources {'✓' if data.get('resources') else '✗'}  prompts {'✓' if data.get('prompts') else '✗'}",
            title=f"MCP Server: {data.get('endpoint') or data.get('url')}",
        )
    )
    table = Table(title=f"Tools ({len(data.get('tools', []))})")
    table.add_column("Name")
    table.add_column("Description")
    console.print(table) if not data.get("tools") else None
    for tool in data.get("tools", []):
        table.add_row(str(tool.get("name", "")), str(tool.get("description", ""))[:80])
    console.print(table)
    # 🔴 Флаги НЕ считаем заново здесь — единственный источник истины security_findings
    # (прежде _render_probe скорил EXEC/NO_SCHEMA отдельно и мог разойтись с находками).
    findings = data.get("security_findings", [])
    if findings:
        console.print(f"[yellow]Находки безопасности: {len(findings)} · вердикт: {data.get('verdict')}[/yellow]")
        for item in findings:
            sev = item.get("severity", "medium")
            цвет = {"critical": "red", "high": "yellow"}.get(sev, "white")
            console.print(f"  [[{цвет}]{sev}[/{цвет}]] {item['code']}: {item['message']}")
    else:
        console.print(f"[green]находок безопасности нет · вердикт: {data.get('verdict')}[/green]")


@click.group(cls=BannerGroup)
def main() -> None:
    """MAD MCP probe."""


@main.command("probe")
@click.argument("url")
@click.option("--json", "as_json", type=click.Path(), default=None,
              help="сохранить JSON-находки по пути (контракт пайплайна, как вся семья)")
def probe_cmd(url: str, as_json: str | None) -> None:
    """Полная проба MCP-сервера."""
    data = asyncio.run(probe_server(url))
    if as_json:
        import pathlib
        pathlib.Path(as_json).write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        console.print(f"JSON: {as_json}")
    # 🔴 rc=2 «не состоялась» ≠ rc=0 «чисто»: MCP не найден — не «сервер безопасен».
    # Проверяем по mcp_detected, а не только по not_proven: при недостижимом сервере probe_server
    # делает ранний return и вердикт-блок не отрабатывает — но mcp_detected остаётся False.
    if not data.get("mcp_detected") or data.get("not_proven"):
        console.print(f"[yellow]НЕ ПРОВЕРЕНО[/yellow]: "
                      f"{data.get('not_proven') or 'MCP-сервер не обнаружен'}")
        raise SystemExit(2)
    _render_probe(data)
    if data.get("critical_findings"):
        raise SystemExit(1)


@main.command("tools")
@click.argument("url")
def tools_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Tools")
    table.add_column("Name")
    table.add_column("Description")
    for tool in data.get("tools", []):
        table.add_row(str(tool.get("name", "")), str(tool.get("description", ""))[:100])
    console.print(table)


@main.command("resources")
@click.argument("url")
def resources_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Resources")
    table.add_column("URI")
    table.add_column("Name")
    for item in data.get("resources", []):
        table.add_row(str(item.get("uri", "")), str(item.get("name", "")))
    console.print(table)


@main.command("prompts")
@click.argument("url")
def prompts_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Prompts")
    table.add_column("Name")
    table.add_column("Description")
    for item in data.get("prompts", []):
        table.add_row(str(item.get("name", "")), str(item.get("description", ""))[:100])
    console.print(table)


@main.command("fingerprint")
@click.argument("url")
def fingerprint_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    console.print_json(data=data.get("fingerprint", {}))


@main.command("security")
@click.argument("url")
def security_cmd(url: str) -> None:
    data = asyncio.run(probe_server(url))
    table = Table(title="Security Findings")
    table.add_column("Code")
    table.add_column("Message")
    for item in data.get("security_findings", []):
        table.add_row(item["code"], item["message"])
    console.print(table)


if __name__ == "__main__":
    main()
