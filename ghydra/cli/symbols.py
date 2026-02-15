"""Symbol table commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('symbols')
def symbols():
    """Symbol table commands.

    Commands for listing symbols, imports, and exports.
    """
    pass


@symbols.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_symbols(ctx, offset, limit):
    """List all symbols in the program.

    \b
    Examples:
        ghydra symbols list
        ghydra symbols list --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        response = client.get('symbols', params=params)
        output = formatter.format_symbols_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@symbols.command('imports')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_imports(ctx, offset, limit):
    """List imported symbols.

    \b
    Examples:
        ghydra symbols imports
        ghydra symbols imports --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        response = client.get('symbols/imports', params=params)
        output = formatter.format_symbols_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@symbols.command('exports')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_exports(ctx, offset, limit):
    """List exported symbols.

    \b
    Examples:
        ghydra symbols exports
        ghydra symbols exports --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        response = client.get('symbols/exports', params=params)
        output = formatter.format_symbols_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
