"""Program analysis commands."""

import json
import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address


@click.group('analysis')
def analysis():
    """Program analysis commands.

    Commands for running and retrieving analysis results.
    """
    pass


@analysis.command('run')
@click.option('--analysis-options', help='Analysis options as JSON dict')
@click.option('--background/--foreground', default=True,
              help='Run analysis in background (default) or block until complete')
@click.pass_context
def run_analysis(ctx, analysis_options, background):
    """Run analysis on the current program.

    \b
    Examples:
        ghydra analysis run
        ghydra analysis run --foreground
        ghydra analysis run --analysis-options '{"functionRecovery": true}'
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        payload = {}

        if analysis_options:
            try:
                opts = json.loads(analysis_options)
                if not isinstance(opts, dict):
                    raise click.BadParameter('--analysis-options must be a JSON object')
                payload.update(opts)
            except json.JSONDecodeError as e:
                click.echo(f"Error: Invalid JSON in --analysis-options: {e}", err=True)
                ctx.exit(1)

        payload.setdefault('background', str(background).lower())

        response = client.post('analysis/run', json_data=payload)
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

    One of --name or --address is required.

    \b
    Examples:
        ghydra analysis get-callgraph --name main
        ghydra analysis get-callgraph --address 0x401000 --max-depth 5
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    if not address and not name:
        rich_echo("Error: one of --name or --address is required", err=True)
        ctx.exit(1)

    try:
        # Server reads "depth"; send both for older builds.
        params = {
            'depth': max_depth,
            'max_depth': max_depth
        }

        if address:
            params['address'] = validate_address(address)
        elif name:
            params['name'] = name

        response = client.get('analysis/callgraph', params=params)
        if hasattr(formatter, "format_callgraph"):
            output = formatter.format_callgraph(response)
        else:
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
        # The server takes the address as a query param, not a path segment.
        params = {
            'address': validate_address(address),
            'direction': direction,
            'max_steps': max_steps
        }

        response = client.get('analysis/dataflow', params=params)
        if hasattr(formatter, "format_dataflow"):
            output = formatter.format_dataflow(response)
        else:
            output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@analysis.command('call-paths')
@click.option('--from', 'from_fn', required=True, help='Source function (name or address)')
@click.option('--to', 'to_fn', required=True, help='Target function (name or address)')
@click.option('--max-depth', type=int, default=5, help='Max path length in edges (default 5, cap 15)')
@click.option('--max-paths', type=int, default=50, help='Max number of paths (default 50, cap 500)')
@click.pass_context
def call_paths(ctx, from_fn, to_fn, max_depth, max_paths):
    """Find bounded call paths between two functions.

    \b
    Examples:
        ghydra analysis call-paths --from main --to fopen
        ghydra analysis call-paths --from 0x401000 --to 0x405abc --max-depth 8
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'from': from_fn, 'to': to_fn, 'max_depth': max_depth, 'max_paths': max_paths}
        response = client.get('analysis/callpaths', params=params)
        if hasattr(formatter, "format_call_paths"):
            output = formatter.format_call_paths(response)
        else:
            output = formatter.format_simple_result(response)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
        ctx.exit(1)


@analysis.command('string-usage')
@click.argument('value')
@click.option('--match', type=click.Choice(['substring', 'regex']), default='substring',
              help='Match mode (default substring)')
@click.option('--caller-depth', type=int, default=0, help='Reverse-call-graph depth (default 0, cap 5)')
@click.option('--limit', type=int, default=50, help='Page size over matched strings')
@click.option('--offset', type=int, default=0, help='Page offset over matched strings')
@click.pass_context
def string_usage(ctx, value, match, caller_depth, limit, offset):
    """Trace which functions use a string (and optionally their callers).

    \b
    Examples:
        ghydra analysis string-usage CreateFileW
        ghydra analysis string-usage "error: %s" --match regex --caller-depth 2
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'value': value, 'match': match, 'caller_depth': caller_depth,
                  'limit': limit, 'offset': offset}
        response = client.get('analysis/strings/usage', params=params)
        if hasattr(formatter, "format_string_usage"):
            output = formatter.format_string_usage(response)
        else:
            output = formatter.format_simple_result(response)
        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)
    except GhidraError as e:
        rich_echo(formatter.format_error(e), err=True)
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
