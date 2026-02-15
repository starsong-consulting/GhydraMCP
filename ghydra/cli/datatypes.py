"""Data type commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('datatypes')
def datatypes():
    """Data type commands.

    Commands for listing and searching data types.
    """
    pass


@datatypes.command('list')
@click.option('--category', help='Filter by category path')
@click.option('--kind', type=click.Choice(['struct', 'enum', 'union']), help='Filter by kind')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_datatypes(ctx, category, kind, offset, limit):
    """List data types defined in the program.

    \b
    Examples:
        ghydra datatypes list
        ghydra datatypes list --kind struct
        ghydra datatypes list --category /MyCategory
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        if category:
            params['category'] = category
        if kind:
            params['kind'] = kind
        response = client.get('datatypes', params=params)
        output = formatter.format_datatypes_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@datatypes.command('search')
@click.argument('name')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def search_datatypes(ctx, name, offset, limit):
    """Search for data types by name.

    \b
    Examples:
        ghydra datatypes search MyStruct
        ghydra datatypes search int
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit, 'name': name}
        response = client.get('datatypes', params=params)
        output = formatter.format_datatypes_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
