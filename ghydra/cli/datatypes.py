"""Data type commands."""

import json

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


@datatypes.command('create-struct')
@click.option('--name', required=True, help='Struct name')
@click.option('--category', default='/', help='Category path (default: /)')
@click.option('--fields-json', help='Optional JSON array string for fields')
@click.pass_context
def create_struct(ctx, name, category, fields_json):
    """Create a struct datatype."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'name': name, 'category': category}
        if fields_json:
            data['fields'] = json.loads(fields_json)

        response = client.post('datatypes/struct', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@datatypes.command('create-enum')
@click.option('--name', required=True, help='Enum name')
@click.option('--size', type=int, default=4, help='Enum storage size in bytes (default: 4)')
@click.option('--category', default='/', help='Category path (default: /)')
@click.option('--values-json', help='Optional JSON object string for values')
@click.pass_context
def create_enum(ctx, name, size, category, values_json):
    """Create an enum datatype."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'name': name, 'size': size, 'category': category}
        if values_json:
            data['values'] = json.loads(values_json)

        response = client.post('datatypes/enum', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@datatypes.command('create-union')
@click.option('--name', required=True, help='Union name')
@click.option('--category', default='/', help='Category path (default: /)')
@click.option('--fields-json', help='Optional JSON array string for fields')
@click.pass_context
def create_union(ctx, name, category, fields_json):
    """Create a union datatype."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'name': name, 'category': category}
        if fields_json:
            data['fields'] = json.loads(fields_json)
        response = client.post('datatypes/union', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
