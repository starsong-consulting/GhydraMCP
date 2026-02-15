"""Variable listing commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('variables')
def variables():
    """Variable commands.

    Commands for listing global and local variables.
    """
    pass


@variables.command('list')
@click.option('--search', help='Filter variables by name')
@click.option('--global-only', is_flag=True, help='Only show global variables')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_variables(ctx, search, global_only, offset, limit):
    """List variables in the program.

    \b
    Examples:
        ghydra variables list
        ghydra variables list --global-only
        ghydra variables list --search counter
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        if search:
            params['search'] = search
        if global_only:
            params['global_only'] = 'true'
        response = client.get('variables', params=params)
        output = formatter.format_variables_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
