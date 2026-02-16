"""Cross-reference analysis commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address


@click.group('xrefs')
def xrefs():
    """Cross-reference analysis commands.

    Commands for analyzing cross-references between code and data.
    """
    pass


@xrefs.command('list')
@click.option('--to-addr', '--to-address', help='Filter references TO this address (hex)')
@click.option('--from-addr', '--from-address', help='Filter references FROM this address (hex)')
@click.option('--type', help='Filter by type (e.g., CALL, READ, WRITE)')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_xrefs(ctx, to_addr, from_addr, type, offset, limit):
    """List cross-references with filtering and pagination.

    At least one of --to-addr or --from-addr must be specified.

    \b
    Examples:
        ghydra xrefs list --to-addr 0x401000
        ghydra xrefs list --from-addr 0x401000
        ghydra xrefs list --to-addr 0x401000 --type CALL
    """
    if not to_addr and not from_addr:
        rich_echo("[red]Error:[/red] Either --to-addr or --from-addr is required", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'offset': offset,
            'limit': limit
        }

        if to_addr:
            params['to_addr'] = validate_address(to_addr)
        if from_addr:
            params['from_addr'] = validate_address(from_addr)
        if type:
            params['type'] = type

        response = client.get('xrefs', params=params)
        output = formatter.format_xrefs(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@xrefs.command('to')
@click.argument('address')
@click.option('--type', help='Filter by type (e.g., CALL, READ, WRITE)')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def xrefs_to(ctx, address, type, offset, limit):
    """Get cross-references TO an address.

    \b
    Examples:
        ghydra xrefs to 0x401000
        ghydra xrefs to 0x401000 --type CALL
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'to_addr': validate_address(address),
            'offset': offset,
            'limit': limit
        }

        if type:
            params['type'] = type

        response = client.get('xrefs', params=params)
        output = formatter.format_xrefs(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@xrefs.command('from')
@click.argument('address')
@click.option('--type', help='Filter by type (e.g., CALL, READ, WRITE)')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def xrefs_from(ctx, address, type, offset, limit):
    """Get cross-references FROM an address.

    \b
    Examples:
        ghydra xrefs from 0x401000
        ghydra xrefs from 0x401000 --type CALL
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'from_addr': validate_address(address),
            'offset': offset,
            'limit': limit
        }

        if type:
            params['type'] = type

        response = client.get('xrefs', params=params)
        output = formatter.format_xrefs(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
