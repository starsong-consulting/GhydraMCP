"""Ghidra script execution commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('scripts')
def scripts():
    """Run Ghidra scripts (must be enabled on the server).

    Requires the Ghidra plugin started with -Dghydra.dev.allowScripts=true (or
    GHYDRA_ALLOW_SCRIPTS=1). Running a script is arbitrary code execution.
    """
    pass


@scripts.command('list')
@click.pass_context
def list_scripts(ctx):
    """List Ghidra scripts available to run."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        response = client.get('scripts')
        output = formatter.format_simple_result(response)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)


@scripts.command('run')
@click.option('--name', help='Name of an existing script (e.g. "MyScript.java")')
@click.option('--file', 'source_file', type=click.Path(exists=True, dir_okay=False),
              help='Path to a GhidraScript source file to run ad-hoc')
@click.option('--arg', 'args', multiple=True, help='Script argument (repeatable)')
@click.pass_context
def run_script(ctx, name, source_file, args):
    """Run a Ghidra script by --name, or ad-hoc from a --file source.

    \b
    Examples:
        ghydra scripts run --name FixupNoReturnFunctionsScript.java
        ghydra scripts run --file ./MassRename.java --arg prefix_
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    if not name and not source_file:
        rich_echo("[red]Error:[/red] one of --name or --file is required", err=True)
        ctx.exit(1)

    payload = {}
    if name:
        payload['name'] = name
    if source_file:
        with open(source_file, 'r') as f:
            payload['source'] = f.read()
    if args:
        payload['args'] = list(args)

    try:
        response = client.post('scripts/run', json_data=payload)
        if ctx.obj['output_json']:
            click.echo(formatter.format_simple_result(response))
            return
        result = response.get('result', {}) or {}
        output = (result.get('output') or '').rstrip()
        if output:
            click.echo(output)
        if result.get('success'):
            rich_echo(f"[green][{result.get('script', 'script')} OK][/green]", err=True)
        else:
            rich_echo(f"[red]Script failed:[/red] {result.get('error')}", err=True)
            ctx.exit(1)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)
