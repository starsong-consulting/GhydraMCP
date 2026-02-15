"""Namespace commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('namespaces')
def namespaces():
    """Namespace commands.

    Commands for listing the namespace hierarchy.
    """
    pass


@namespaces.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_namespaces(ctx, offset, limit):
    """List namespaces in the program.

    \b
    Examples:
        ghydra namespaces list
        ghydra namespaces list --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        response = client.get('namespaces', params=params)
        output = formatter.format_namespaces_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
