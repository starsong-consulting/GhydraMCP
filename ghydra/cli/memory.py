"""Memory operations commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo, validate_address


@click.group('memory')
def memory():
    """Memory read/write commands.

    Commands for reading and writing raw memory in the binary.
    """
    pass


@memory.command('read')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--length', type=int, default=16, help='Number of bytes to read')
@click.option('--format', type=click.Choice(['hex', 'base64', 'string']), default='hex', help='Output format')
@click.pass_context
def read_memory(ctx, address, length, format):
    """Read bytes from memory.

    \b
    Examples:
        ghydra memory read --address 0x401000
        ghydra memory read --address 0x401000 --length 64
        ghydra memory read --address 0x401000 --format string
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'address': validate_address(address),
            'length': length,
            'format': format
        }

        response = client.get('memory', params=params)
        output = formatter.format_memory(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@memory.command('disassemble')
@click.option('--address', '-a', required=True, help='Start address (hex)')
@click.option('--limit', '-l', type=int, default=50, help='Max instructions to return (default: 50)')
@click.option('--offset', '-o', type=int, default=0, help='Instructions to skip')
@click.pass_context
def disassemble_at(ctx, address, limit, offset):
    """Disassemble instructions at an arbitrary address.

    Unlike 'functions disassemble', this is not tied to a function boundary.

    \b
    Examples:
        ghydra memory disassemble --address 0x401000
        ghydra memory disassemble -a 0x401000 --limit 20
        ghydra memory disassemble -a 0x401000 --offset 10 --limit 30
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {'limit': limit}
        if offset > 0:
            params['offset'] = offset

        response = client.get(f'memory/{validate_address(address)}/disassembly', params=params)
        output = formatter.format_disassembly(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@memory.command('write')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--bytes-data', required=True, help='Data to write')
@click.option('--format', type=click.Choice(['hex', 'base64', 'string']), default='hex', help='Input format')
@click.pass_context
def write_memory(ctx, address, bytes_data, format):
    """Write bytes to memory (use with caution).

    \b
    Examples:
        ghydra memory write --address 0x401000 --bytes-data "4883EC10"
        ghydra memory write --address 0x401000 --bytes-data "Hello" --format string
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {
            'bytes': bytes_data,
            'format': format
        }

        response = client.post(f'memory/{validate_address(address)}', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
