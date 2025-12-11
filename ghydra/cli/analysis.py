"""Program analysis commands."""

import json
import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('analysis')
def analysis():
    """Program analysis commands.

    Commands for running and retrieving analysis results.
    """
    pass


@analysis.command('run')
@click.option('--analysis-options', help='Analysis options as JSON dict')
@click.pass_context
def run_analysis(ctx, analysis_options):
    """Run analysis on the current program.

    \b
    Examples:
        ghydra analysis run
        ghydra analysis run --analysis-options '{"functionRecovery": true}'
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {}

        if analysis_options:
            try:
                data['options'] = json.loads(analysis_options)
            except json.JSONDecodeError as e:
                click.echo(f"Error: Invalid JSON in --analysis-options: {e}", err=True)
                ctx.exit(1)

        response = client.post('analysis', json_data=data if data else None)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('get-callgraph')
@click.option('--name', help='Starting function name')
@click.option('--address', '-a', help='Starting function address (hex)')
@click.option('--max-depth', type=int, default=3, help='Max call depth (increase to 10-15 for complex functions)')
@click.pass_context
def get_callgraph(ctx, name, address, max_depth):
    """Get function call graph visualization data.

    If neither --name nor --address is provided, uses entry point.

    \b
    Examples:
        ghydra analysis get-callgraph --name main
        ghydra analysis get-callgraph --address 0x401000 --max-depth 5
        ghydra analysis get-callgraph  # Uses entry point
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'max_depth': max_depth
        }

        if name:
            from urllib.parse import quote
            endpoint = f'analysis/callgraph/by-name/{quote(name)}'
        elif address:
            endpoint = f'analysis/callgraph/{address.lstrip("0x")}'
        else:
            endpoint = 'analysis/callgraph'

        response = client.get(endpoint, params=params)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('get-dataflow')
@click.option('--address', '-a', required=True, help='Starting address (hex)')
@click.option('--direction', type=click.Choice(['forward', 'backward']), default='forward', help='Analysis direction')
@click.option('--max-steps', type=int, default=50, help='Max analysis steps')
@click.pass_context
def get_dataflow(ctx, address, direction, max_steps):
    """Perform data flow analysis from an address.

    \b
    Examples:
        ghydra analysis get-dataflow --address 0x401000
        ghydra analysis get-dataflow --address 0x401000 --direction backward
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'direction': direction,
            'max_steps': max_steps
        }

        response = client.get(f'analysis/dataflow/{address.lstrip("0x")}', params=params)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('status')
@click.pass_context
def status(ctx):
    """Get analysis status for the current program.

    \b
    Example:
        ghydra analysis status
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('analysis/status')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
