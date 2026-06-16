"""Scalar (constant) search commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('scalars')
def scalars():
    """Search for scalar (constant) values in instructions.

    Like Ghidra's "Search For Scalars": find where a constant appears as an
    instruction operand.
    """
    pass


@scalars.command('search')
@click.argument('value')
@click.option('--in-function',
              help='Only matches inside functions whose name contains this (case-insensitive). '
                   'Preferred on large binaries: scans only the matching functions.')
@click.option('--to-function',
              help='Only matches feeding a nearby call to a function whose name contains this '
                   '(e.g. the 0 passed to memset).')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def search_scalars(ctx, value, in_function, to_function, offset, limit):
    """Search for occurrences of a scalar VALUE (hex 0x... or decimal) in instructions.

    \b
    Examples:
        ghydra scalars search 0x1000
        ghydra scalars search 0 --to-function memset
        ghydra scalars search 0x10 --in-function main
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'value': value, 'offset': offset, 'limit': limit}
        if in_function:
            params['in_function'] = in_function
        if to_function:
            params['to_function'] = to_function

        response = client.get('scalars', params=params)
        output = formatter.format_scalars(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
