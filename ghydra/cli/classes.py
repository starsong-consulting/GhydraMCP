"""Class and namespace listing commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('classes')
def classes():
    """Class and namespace commands.

    Commands for listing classes and namespaces in the program.
    """
    pass


@classes.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_classes(ctx, offset, limit):
    """List classes and namespaces.

    \b
    Examples:
        ghydra classes list
        ghydra classes list --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        response = client.get('classes', params=params)
        output = formatter.format_classes_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
