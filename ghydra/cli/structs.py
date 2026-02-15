"""Struct data type management commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('structs')
def structs():
    """Struct data type management commands.

    Commands for creating and managing struct data types.
    """
    pass


@structs.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.option('--category', help='Filter by category path (e.g., "/winapi")')
@click.pass_context
def list_structs(ctx, offset, limit, category):
    """List all struct data types in the program.

    \b
    Examples:
        ghydra structs list
        ghydra structs list --category "/winapi"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'offset': offset,
            'limit': limit
        }

        if category:
            params['category'] = category

        response = client.get('structs', params=params)
        output = formatter.format_structs_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@structs.command('get')
@click.option('--name', required=True, help='Struct name')
@click.pass_context
def get_struct(ctx, name):
    """Get detailed information about a specific struct.

    \b
    Example:
        ghydra structs get --name "MyStruct"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        from urllib.parse import quote
        response = client.get(f'structs/{quote(name)}')
        output = formatter.format_struct_info(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@structs.command('create')
@click.option('--name', required=True, help='Struct name')
@click.option('--category', help='Category path (e.g., "/custom")')
@click.option('--description', help='Struct description')
@click.pass_context
def create_struct(ctx, name, category, description):
    """Create a new struct data type.

    \b
    Examples:
        ghydra structs create --name "MyStruct"
        ghydra structs create --name "MyStruct" --category "/custom"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'name': name}

        if category:
            data['category'] = category
        if description:
            data['description'] = description

        response = client.post('structs', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@structs.command('add-field')
@click.option('--struct-name', required=True, help='Struct name')
@click.option('--field-name', required=True, help='Field name')
@click.option('--field-type', required=True, help='Data type (e.g., int, char, pointer)')
@click.option('--offset', type=int, help='Specific offset (appends to end if not specified)')
@click.option('--comment', help='Field comment')
@click.pass_context
def add_field(ctx, struct_name, field_name, field_type, offset, comment):
    """Add a field to an existing struct.

    \b
    Examples:
        ghydra structs add-field --struct-name "MyStruct" --field-name "field1" --field-type "int"
        ghydra structs add-field --struct-name "MyStruct" --field-name "field2" --field-type "char" --offset 4
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        from urllib.parse import quote
        data = {
            'name': field_name,
            'type': field_type
        }

        if offset is not None:
            data['offset'] = offset
        if comment:
            data['comment'] = comment

        response = client.post(f'structs/{quote(struct_name)}/fields', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@structs.command('update-field')
@click.option('--struct-name', required=True, help='Struct name')
@click.option('--field-name', help='Field name (use this OR --field-offset)')
@click.option('--field-offset', type=int, help='Field offset (use this OR --field-name)')
@click.option('--new-name', help='New field name')
@click.option('--new-type', help='New data type')
@click.option('--new-comment', help='New comment')
@click.pass_context
def update_field(ctx, struct_name, field_name, field_offset, new_name, new_type, new_comment):
    """Update an existing field in a struct.

    At least one of --new-name, --new-type, or --new-comment must be specified.

    \b
    Examples:
        ghydra structs update-field --struct-name "MyStruct" --field-name "field1" --new-type "uint32_t"
        ghydra structs update-field --struct-name "MyStruct" --field-offset 0 --new-name "newField1"
    """
    if not field_name and field_offset is None:
        rich_echo("[red]Error:[/red] Either --field-name or --field-offset is required", err=True)
        ctx.exit(1)

    if field_name and field_offset is not None:
        rich_echo("[red]Error:[/red] Cannot specify both --field-name and --field-offset", err=True)
        ctx.exit(1)

    if not new_name and not new_type and not new_comment:
        rich_echo("[red]Error:[/red] At least one of --new-name, --new-type, or --new-comment is required", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        from urllib.parse import quote
        data = {}

        if new_name:
            data['name'] = new_name
        if new_type:
            data['type'] = new_type
        if new_comment:
            data['comment'] = new_comment

        field_id = quote(field_name) if field_name else str(field_offset)
        response = client.patch(f'structs/{quote(struct_name)}/fields/{field_id}', data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@structs.command('delete')
@click.option('--name', required=True, help='Struct name')
@click.pass_context
def delete_struct(ctx, name):
    """Delete a struct data type.

    \b
    Example:
        ghydra structs delete --name "MyStruct"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        from urllib.parse import quote
        response = client.delete(f'structs/{quote(name)}')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
