"""Command-line interface for PolicyVibes.

Uses Claude Agent SDK for LLM-powered ToS violation detection.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.spinner import Spinner
from rich.text import Text

from . import __version__
from .agent import create_policyvibes_agent_definition, load_prompt

console = Console()

# Import Claude Agent SDK (required for LLM-powered scanning)
try:
    from claude_agent_sdk import query, ClaudeAgentOptions
except ImportError:
    query = None
    ClaudeAgentOptions = None


async def run_agent_scan(repo_path: str, model: str = "sonnet") -> dict:
    """Run policy scan using Claude Agent SDK.

    Args:
        repo_path: Path to repository to scan
        model: Model to use (sonnet, opus, haiku)

    Returns:
        Dictionary with scan results
    """
    if query is None or ClaudeAgentOptions is None:
        raise RuntimeError(
            "Claude Agent SDK not installed. "
            "Install with: pip install claude-agent-sdk"
        )

    # Create agent options
    options = ClaudeAgentOptions(
        setting_sources=["project"],  # Load skills from .claude/skills
        allowed_tools=["Read", "Grep", "Glob", "Skill", "Write", "Task"],
        agents=create_policyvibes_agent_definition(model),
        cwd=repo_path,
    )

    prompt = f"""Scan the repository at {repo_path} for Anthropic Terms of Service violations.

Use the compliance detection skills in .claude/skills/compliance/ to identify:
1. OAuth token abuse - using subscription tokens as API keys
2. Header spoofing - impersonating Claude Code
3. Credential extraction - reading from Claude CLI config files
4. Subscription routing - proxying OAuth tokens

Follow the detection pipeline for each skill:
- Phase 1: Identify candidate patterns
- Phase 2: Verify context (is this actual abuse or just documentation/tests?)
- Phase 3: Classify severity (ACTIVE_VIOLATION or POTENTIAL_VIOLATION)
- Phase 4: Generate specific remediation guidance

Output your findings to POLICYVIBES_REPORT.json with the structure specified in the main prompt.
"""

    results = {
        "messages": [],
        "report_path": None,
        "error": None,
    }

    console.print(Panel(
        f"[bold]PolicyVibes v{__version__}[/bold]\n"
        f"Scanning: {repo_path}\n"
        f"Model: {model}",
        style="blue",
    ))
    console.print()

    with Live(Spinner("dots", text="Analyzing repository..."), refresh_per_second=4) as live:
        try:
            async for message in query(prompt=prompt, options=options):
                if hasattr(message, "content"):
                    # Accumulate text content
                    if isinstance(message.content, str):
                        results["messages"].append(message.content)
                        live.update(Text(f"[dim]{message.content[:80]}...[/dim]" if len(message.content) > 80 else message.content))
                    elif isinstance(message.content, list):
                        for block in message.content:
                            if hasattr(block, "text"):
                                results["messages"].append(block.text)

                # Check if report was written
                if hasattr(message, "tool_use") and message.tool_use:
                    for tool in message.tool_use if isinstance(message.tool_use, list) else [message.tool_use]:
                        if hasattr(tool, "name") and tool.name == "Write":
                            if "POLICYVIBES_REPORT" in str(getattr(tool, "input", {})):
                                results["report_path"] = Path(repo_path) / "POLICYVIBES_REPORT.json"

        except Exception as e:
            results["error"] = str(e)

    return results


def display_report(report_path: Path):
    """Display the policy report."""
    if not report_path.exists():
        console.print("[yellow]No report file generated.[/yellow]")
        return None

    try:
        with open(report_path) as f:
            report = json.load(f)

        console.print()
        console.print(Panel("[bold]PolicyVibes Report[/bold]", style="green"))

        # Summary
        summary = report.get("summary", {})
        active = summary.get("active_violations", 0)
        potential = summary.get("potential_violations", 0)

        console.print(f"  Files scanned: {summary.get('files_scanned', 'N/A')}")
        console.print(f"  Active violations: [red]{active}[/red]")
        console.print(f"  Potential violations: [yellow]{potential}[/yellow]")
        console.print()

        # Findings
        findings = report.get("findings", [])
        if findings:
            console.print("[bold]Findings:[/bold]")
            for finding in findings:
                severity = finding.get("severity", "UNKNOWN")
                color = "red" if severity == "ACTIVE_VIOLATION" else "yellow"

                console.print(f"\n  [{color}]{severity}[/{color}] [{finding.get('type', 'unknown')}]")
                console.print(f"    File: [blue]{finding.get('file', 'N/A')}:{finding.get('line', 'N/A')}[/blue]")
                console.print(f"    Code: {finding.get('code', 'N/A')[:80]}...")
                console.print(f"    Reason: {finding.get('reason', 'N/A')}")
                if finding.get("remediation"):
                    console.print(f"    [green]Remediation: {finding.get('remediation')}[/green]")

        return report

    except json.JSONDecodeError as e:
        console.print(f"[red]Error parsing report: {e}[/red]")
        return None


def run_sync_scan(repo_path: str, model: str) -> dict:
    """Run scan synchronously."""
    return asyncio.run(run_agent_scan(repo_path, model))


@click.group()
@click.version_option(version=__version__)
def main():
    """PolicyVibes - Claude Agent SDK-based ToS violation detection."""
    pass


@main.command()
@click.argument("path", type=click.Path(exists=True))
@click.option(
    "--model", "-m",
    type=click.Choice(["sonnet", "opus", "haiku"]),
    default="sonnet",
    help="Model to use for analysis (default: sonnet)",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format (default: text)",
)
def scan(path: str, model: str, output: str):
    """Scan a repository for Anthropic ToS violations.

    PATH is the directory to scan.

    This uses Claude Agent SDK to perform LLM-powered analysis,
    going beyond simple regex matching to understand context and intent.

    Exit codes:
        0 - No violations found
        1 - Violations found
        2 - Error occurred
    """
    if query is None or ClaudeAgentOptions is None:
        console.print(
            "[red]Claude Agent SDK not installed.[/red]\n"
            "Install with: pip install claude-agent-sdk"
        )
        sys.exit(2)

    try:
        results = run_sync_scan(path, model)

        if results.get("error"):
            console.print(f"[red]Error: {results['error']}[/red]")
            sys.exit(2)

        # Display accumulated messages
        if results.get("messages"):
            console.print()
            console.print(Panel("[bold]Agent Analysis[/bold]", style="cyan"))
            for msg in results["messages"][-3:]:  # Show last few messages
                console.print(Markdown(msg[:500]))

        # Display report if generated
        report_path = results.get("report_path") or Path(path) / "POLICYVIBES_REPORT.json"
        report = display_report(report_path)

        if report:
            summary = report.get("summary", {})
            if summary.get("active_violations", 0) > 0 or summary.get("potential_violations", 0) > 0:
                sys.exit(1)

        sys.exit(0)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(2)


@main.command("list-skills")
def list_skills():
    """List available policy detection skills."""
    skills_dir = Path(__file__).parent.parent.parent.parent / ".claude" / "skills" / "compliance"

    if not skills_dir.exists():
        # Try from current working directory
        skills_dir = Path.cwd() / ".claude" / "skills" / "compliance"

    if not skills_dir.exists():
        console.print("[yellow]No skills directory found.[/yellow]")
        console.print("Expected at: .claude/skills/compliance/")
        return

    console.print(Panel("[bold]PolicyVibes Detection Skills[/bold]", style="blue"))

    for skill_dir in sorted(skills_dir.iterdir()):
        if skill_dir.is_dir():
            skill_md = skill_dir / "SKILL.md"
            if skill_md.exists():
                # Parse YAML frontmatter
                content = skill_md.read_text()
                lines = content.split("\n")

                name = skill_dir.name
                description = ""

                # Simple frontmatter parsing
                in_frontmatter = False
                for line in lines:
                    if line.strip() == "---":
                        in_frontmatter = not in_frontmatter
                        continue
                    if in_frontmatter:
                        if line.startswith("description:"):
                            description = line.split(":", 1)[1].strip()

                console.print(f"\n  [cyan]{name}[/cyan]")
                if description:
                    console.print(f"    {description}")


if __name__ == "__main__":
    main()
