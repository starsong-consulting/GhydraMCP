"""Data item management commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('data')
def data():
    """Data item management commands.

    Commands for working with defined data items in the binary.
    """
    pass


@data.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.option('--addr', help='Filter by exact address (hex)')
@click.option('--name', help='Filter by exact name (case-sensitive)')
@click.option('--name-contains', help='Filter by name substring (case-insensitive)')
@click.option('--type', help='Filter by data type')
@click.pass_context
def list_data(ctx, offset, limit, addr, name, name_contains, type):
    """List defined data items with optional filtering.

    \b
    Examples:
        ghydra data list
        ghydra data list --type string
        ghydra data list --name-contains "user"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'offset': offset,
            'limit': limit
        }

        if addr:
            params['addr'] = addr.lstrip('0x')
        if name:
            params['name'] = name
        if name_contains:
            params['name_contains'] = name_contains
        if type:
            params['type'] = type

        response = client.get('data', params=params)
        output = formatter.format_data_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@data.command('list-strings')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=2000, help='Maximum results to return')
@click.option('--filter', help='Filter strings by content')
@click.pass_context
def list_strings(ctx, offset, limit, filter):
    """List all defined strings in the binary.

    \b
    Examples:
        ghydra data list-strings
        ghydra data list-strings --limit 100
        ghydra data list-strings --filter "error"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'offset': offset,
            'limit': limit
        }

        if filter:
            params['filter'] = filter

        response = client.get('data/strings', params=params)
        output = formatter.format_strings_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@data.command('create')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--data-type', required=True, help='Data type (e.g., string, dword, byte)')
@click.option('--size', type=int, help='Size in bytes (if applicable)')
@click.pass_context
def create_data(ctx, address, data_type, size):
    """Define a new data item at specified address.

    \b
    Examples:
        ghydra data create --address 0x401000 --data-type string
        ghydra data create --address 0x401000 --data-type dword
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {
            'type': data_type
        }

        if size:
            data['size'] = size

        response = client.post(f'data/{address.lstrip("0x")}', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@data.command('rename')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--name', required=True, help='New name for the data item')
@click.pass_context
def rename_data(ctx, address, name):
    """Rename a data item.

    \b
    Example:
        ghydra data rename --address 0x401000 --name "user_string"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'name': name}
        response = client.patch(f'data/{address.lstrip("0x")}', data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@data.command('delete')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.pass_context
def delete_data(ctx, address):
    """Delete data at specified address.

    \b
    Example:
        ghydra data delete --address 0x401000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.delete(f'data/{address.lstrip("0x")}')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@data.command('set-type')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--data-type', required=True, help='Data type name (e.g., uint32_t, char[10])')
@click.pass_context
def set_type(ctx, address, data_type):
    """Set the data type of a data item.

    \b
    Examples:
        ghydra data set-type --address 0x401000 --data-type "uint32_t"
        ghydra data set-type --address 0x401000 --data-type "char[10]"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'type': data_type}
        response = client.patch(f'data/{address.lstrip("0x")}/type', data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
