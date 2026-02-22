"""Function analysis commands."""

import click
from urllib.parse import quote

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address

DEFAULT_DECOMPILATION_TIMEOUT = 1200


@click.group('functions')
def functions():
    """Function analysis and manipulation commands.

    Commands for listing, analyzing, and modifying functions in the binary.
    """
    pass


@functions.command('list')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.option('--name-contains', help='Filter by function name substring (case-insensitive)')
@click.option('--name-matches', help='Filter by function name regex pattern')
@click.option('--containing-address', help='Find function containing this address (hex)')
@click.option('--addr-min', help='Only return functions at or above this address (hex)')
@click.option('--addr-max', help='Only return functions at or below this address (hex)')
@click.pass_context
def list_functions(ctx, offset, limit, name_contains, name_matches, containing_address,
                   addr_min, addr_max):
    """List all functions with optional filtering.

    \b
    Examples:
        ghydra functions list
        ghydra functions list --name-contains main
        ghydra functions list --name-matches "^sub_.*"
        ghydra functions list --containing-address 0x401234
        ghydra functions list --addr-min 0x401000 --addr-max 0x402000
        ghydra functions list --limit 50
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'offset': offset,
            'limit': limit
        }

        if name_contains:
            params['name_contains'] = name_contains
        if name_matches:
            params['name_matches_regex'] = name_matches
        if containing_address:
            params['containing_addr'] = validate_address(containing_address)
        if addr_min:
            params['addr_min'] = validate_address(addr_min)
        if addr_max:
            params['addr_max'] = validate_address(addr_max)

        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('search')
@click.argument('name')
@click.option('--regex', '-r', is_flag=True, help='Treat NAME as a regex pattern')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def search_functions(ctx, name, regex, offset, limit):
    """Search for functions by name.

    \b
    Examples:
        ghydra functions search ClassifyStar
        ghydra functions search main
        ghydra functions search --regex "^sub_.*"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'offset': offset, 'limit': limit}
        if regex:
            params['name_matches_regex'] = name
        else:
            params['name_contains'] = name

        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-containing')
@click.argument('address')
@click.pass_context
def get_containing(ctx, address):
    """Find the function containing the specified address.

    \b
    Example:
        ghydra functions get-containing 0x401234
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'containing_addr': validate_address(address)}
        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-next')
@click.argument('address')
@click.pass_context
def get_next(ctx, address):
    """Get the next function after the given address (by memory order).

    \b
    Example:
        ghydra functions get-next 0x401000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'after': validate_address(address)}
        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-prev')
@click.argument('address')
@click.pass_context
def get_prev(ctx, address):
    """Get the previous function before the given address (by memory order).

    \b
    Example:
        ghydra functions get-prev 0x402000
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'before': validate_address(address)}
        response = client.get('functions', params=params)
        output = formatter.format_functions_list(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def get_function(ctx, name, address):
    """Get detailed information about a function.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions get --name main
        ghydra functions get --address 0x401000
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}'

        # Make API request
        response = client.get(endpoint)

        output = formatter.format_function_info(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('decompile')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--syntax-tree', is_flag=True, help='Include syntax tree in output')
@click.option('--style', default='normalize', help='Decompiler style (default: normalize)')
@click.option('--no-constants', is_flag=True, help='Hide constant values')
@click.option('--timeout', type=int, default=DEFAULT_DECOMPILATION_TIMEOUT,
              help=f'Decompilation timeout in seconds (default: {DEFAULT_DECOMPILATION_TIMEOUT})')
@click.option('--start-line', type=int, help='Start line (1-indexed)')
@click.option('--end-line', type=int, help='End line (inclusive)')
@click.option('--max-lines', type=int, help='Maximum lines to return')
@click.pass_context
def decompile(ctx, name, address, syntax_tree, style, no_constants, timeout, start_line, end_line, max_lines):
    """Decompile a function to C pseudocode.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions decompile --name main
        ghydra functions decompile --address 0x401000
        ghydra functions decompile --name main --start-line 10 --end-line 20
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}/decompile'
        else:
            endpoint = f'functions/by-name/{quote(name)}/decompile'

        # Build query parameters
        params = {
            'syntax_tree': str(syntax_tree).lower(),
            'style': style,
            'show_constants': str(not no_constants).lower(),
            'timeout': timeout
        }

        if start_line:
            params['start_line'] = start_line
        if end_line:
            params['end_line'] = end_line
        if max_lines:
            params['max_lines'] = max_lines

        # Keep HTTP timeout slightly above requested decompilation timeout
        # so client transport timeout does not fire first.
        original_timeout = client.timeout
        client.timeout = max(original_timeout, timeout + 30)
        try:
            response = client.get(endpoint, params=params)
        finally:
            client.timeout = original_timeout

        output = formatter.format_decompiled_code(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('disassemble')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--offset', '-o', default=0, type=int, help='Number of instructions to skip')
@click.option('--limit', '-l', default=0, type=int, help='Max instructions to return (0 = all)')
@click.pass_context
def disassemble(ctx, name, address, offset, limit):
    """Get disassembly for a function.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions disassemble --name main
        ghydra functions disassemble --address 0x401000
        ghydra functions disassemble --name main --offset 50 --limit 100
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        if address:
            endpoint = f'functions/{validate_address(address)}/disassembly'
        else:
            endpoint = f'functions/by-name/{quote(name)}/disassembly'

        params = {}
        if offset > 0:
            params['offset'] = offset
        if limit > 0:
            params['limit'] = limit

        response = client.get(endpoint, params=params)

        output = formatter.format_disassembly(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('create')
@click.option('--address', '-a', required=True, help='Address for new function (hex)')
@click.pass_context
def create_function(ctx, address):
    """Create a new function at specified address.

    \b
    Example:
        ghydra functions create --address 0x401500
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.post('functions', json_data={'address': validate_address(address)})

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('rename')
@click.option('--old-name', help='Current function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--new-name', required=True, help='New function name')
@click.pass_context
def rename_function(ctx, old_name, address, new_name):
    """Rename a function.

    Either --old-name or --address must be specified.

    \b
    Examples:
        ghydra functions rename --old-name sub_401000 --new-name main
        ghydra functions rename --address 0x401000 --new-name main
    """
    if not old_name and not address:
        rich_echo("[red]Error:[/red] Either --old-name or --address is required", err=True)
        ctx.exit(1)

    if old_name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --old-name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(old_name)}'

        # Make API request
        data = {'name': new_name}
        response = client.patch(endpoint, data=data)

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('set-signature')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.option('--signature', required=True, help='Function signature (e.g., "int func(char *data, int size)")')
@click.pass_context
def set_signature(ctx, name, address, signature):
    """Set function signature/prototype.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions set-signature --name main --signature "int main(int argc, char **argv)"
        ghydra functions set-signature --address 0x401000 --signature "void func(void)"
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}'

        # Make API request
        data = {'signature': signature}
        response = client.patch(endpoint, data=data)

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('delete')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def delete_function(ctx, name, address):
    """Delete a function."""
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        if address:
            endpoint = f'functions/{validate_address(address)}'
        else:
            endpoint = f'functions/by-name/{quote(name)}'

        response = client.delete(endpoint)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('get-variables')
@click.option('--name', '-n', help='Function name')
@click.option('--address', '-a', help='Function address (hex)')
@click.pass_context
def get_variables(ctx, name, address):
    """Get variables for a function.

    Either --name or --address must be specified.

    \b
    Examples:
        ghydra functions get-variables --name main
        ghydra functions get-variables --address 0x401000
    """
    if not name and not address:
        rich_echo("[red]Error:[/red] Either --name or --address is required", err=True)
        ctx.exit(1)

    if name and address:
        rich_echo("[red]Error:[/red] Cannot specify both --name and --address", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        # Build endpoint
        if address:
            endpoint = f'functions/{validate_address(address)}/variables'
        else:
            endpoint = f'functions/by-name/{quote(name)}/variables'

        # Make API request
        response = client.get(endpoint)

        output = formatter.format_function_info(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('update-variable')
@click.option('--address', '-a', required=True, help='Function address (hex)')
@click.option('--variable-name', required=True, help='Existing variable name')
@click.option('--new-name', help='New variable name')
@click.option('--new-data-type', help='New variable data type')
@click.pass_context
def update_variable(ctx, address, variable_name, new_name, new_data_type):
    """Update a local variable in a function."""
    if not new_name and not new_data_type:
        rich_echo("[red]Error:[/red] At least one of --new-name or --new-data-type is required", err=True)
        ctx.exit(1)

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        endpoint = f'functions/{validate_address(address)}/variables/{quote(variable_name)}'
        data = {}
        if new_name:
            data['name'] = new_name
        if new_data_type:
            data['data_type'] = new_data_type

        response = client.patch(endpoint, data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@functions.command('set-comment')
@click.option('--address', '-a', required=True, help='Function address (hex)')
@click.option('--comment', required=True, help='Comment text')
@click.pass_context
def set_comment(ctx, address, comment):
    """Set comment for a function.

    \b
    Example:
        ghydra functions set-comment --address 0x401000 --comment "Main entry point"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        endpoint = f'functions/{validate_address(address)}'
        data = {'comment': comment}
        response = client.patch(endpoint, data=data)

        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
