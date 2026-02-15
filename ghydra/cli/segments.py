"""Memory segment commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('segments')
def segments():
    """Memory segment commands.

    Commands for listing memory segments/blocks and their permissions.
    """
    pass


@segments.command('list')
@click.option('--name', help='Filter segments by name')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_segments(ctx, name, offset, limit):
    """List memory segments/blocks.

    \b
    Examples:
        ghydra segments list
        ghydra segments list --name .text
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        if name:
            params['name'] = name
        response = client.get('segments', params=params)
        output = formatter.format_segments_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
