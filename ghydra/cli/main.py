"""Main CLI entry point for ghydra command."""

import sys
import click

from ..client import GhidraHTTPClient
from ..config import ConfigManager, GhidraConfig
from ..formatters import JSONFormatter, TableFormatter


@click.group()
@click.option('--host', '-h', envvar='GHYDRA_HOST', help='Ghidra host (default: from config or localhost)')
@click.option('--port', '-p', type=int, envvar='GHYDRA_PORT', help='Ghidra port (default: from config or 8192)')
@click.option('--json', 'output_json', is_flag=True, help='Output raw JSON instead of formatted text')
@click.option('--no-color', is_flag=True, help='Disable colored output')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.version_option(version='2.2.0', prog_name='ghydra')
@click.pass_context
def cli(ctx, host, port, output_json, no_color, verbose):
    """Ghydra CLI - Interact with Ghidra reverse engineering tool.

    This CLI provides command-line access to all Ghidra functionality exposed
    by the GhydraMCP plugin via a HATEOAS REST API.

    \b
    Examples:
        # List all Ghidra instances
        ghydra instances list

        # Decompile a function
        ghydra functions decompile --name main

        # Read memory as hex dump
        ghydra memory read --address 0x401000 --length 64

        # List all strings
        ghydra data list-strings

    \b
    Configuration:
        Configuration file: ~/.ghydra/config.json
        Environment variables: GHYDRA_HOST, GHYDRA_PORT

    For more information, visit: https://github.com/starsong-consulting/GhydraMCP
    """
    # Load configuration
    try:
        config = ConfigManager.load(verbose=verbose)
    except Exception as e:
        if verbose:
            click.echo(f"Warning: Failed to load config: {e}", err=True)
        config = GhidraConfig()

    # Override with CLI options
    if host:
        config.default_host = host
    if port:
        config.default_port = port
    if no_color:
        config.use_colors = False

    # Create HTTP client
    client = GhidraHTTPClient(
        host=config.default_host,
        port=config.default_port,
        timeout=config.timeout
    )

    # Create formatter
    if output_json:
        formatter = JSONFormatter(pretty=True)
    else:
        formatter = TableFormatter(use_colors=config.use_colors)

    # Store in context for subcommands
    ctx.ensure_object(dict)
    ctx.obj['config'] = config
    ctx.obj['verbose'] = verbose
    ctx.obj['client'] = client
    ctx.obj['formatter'] = formatter
    ctx.obj['output_json'] = output_json


# Import and register command groups
from . import (
    instances,
    functions,
    memory,
    data,
    structs,
    xrefs,
    analysis,
    ui,
    comments,
    project
)

cli.add_command(instances.instances)
cli.add_command(functions.functions)
cli.add_command(memory.memory)
cli.add_command(data.data)
cli.add_command(structs.structs)
cli.add_command(xrefs.xrefs)
cli.add_command(analysis.analysis)
cli.add_command(ui.ui)
cli.add_command(comments.comments)
cli.add_command(project.project)


@cli.command('version')
def version_cmd():
    """Show version information."""
    click.echo("ghydra version 2.2.0")
    click.echo("Ghydra CLI for Ghidra reverse engineering tool")


if __name__ == '__main__':
    cli()
