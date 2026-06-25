"""Emulation (PCode) commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo, validate_address


@click.group('emulation')
def emulation():
    """PCode emulation commands (run/step a function, inspect state)."""
    pass


def _emit(ctx, response):
    formatter = ctx.obj['formatter']
    click.echo(formatter.format_simple_result(response))


@emulation.command('reset')
@click.option('--start', '-s', required=True, help='Start address (hex); PC is set here')
@click.pass_context
def reset(ctx, start):
    """Start a fresh emulation session at an address."""
    client = ctx.obj['client']
    try:
        response = client.post('emulation/reset', json_data={'start': validate_address(start)})
        _emit(ctx, response)
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('run')
@click.option('--until', '-u', help='Stop address (hex)')
@click.option('--max-steps', type=int, default=100000, help='Step cap (default 100000)')
@click.option('--trace/--no-trace', default=False, help='Return executed instruction addresses')
@click.pass_context
def run(ctx, until, max_steps, trace):
    """Run until an address, breakpoint, error, or max-steps."""
    client = ctx.obj['client']
    try:
        data = {'max_steps': max_steps, 'trace': trace}
        if until:
            data['until'] = validate_address(until)
        _emit(ctx, client.post('emulation/run', json_data=data))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('step')
@click.option('--count', '-c', type=int, default=1, help='Instructions to step')
@click.option('--trace/--no-trace', default=False)
@click.pass_context
def step(ctx, count, trace):
    """Single-step the session."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.post('emulation/step', json_data={'count': count, 'trace': trace}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('state')
@click.pass_context
def state(ctx):
    """Show current emulation state."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get('emulation/state'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('read-mem')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.option('--length', '-l', type=int, default=64, help='Bytes to read')
@click.pass_context
def read_mem(ctx, address, length):
    """Read emulated memory as hex (e.g. dump decrypted data)."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get(f'emulation/memory/{validate_address(address)}',
                              params={'length': length}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('read-register')
@click.option('--name', '-n', required=True, help='Register name (e.g. RAX)')
@click.pass_context
def read_register(ctx, name):
    """Read an emulated register value (hex)."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get(f'emulation/registers/{name}'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('write-register')
@click.option('--name', '-n', required=True, help='Register name (e.g. RAX)')
@click.option('--value', '-v', required=True, help='Value (hex, e.g. 0xdeadbeef)')
@click.pass_context
def write_register(ctx, name, value):
    """Write an emulated register value."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.post('emulation/registers', json_data={'name': name, 'value': value}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('write-mem')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.option('--hex', '-x', 'hex_bytes', required=True, help='Hex byte string (e.g. 9090)')
@click.pass_context
def write_mem(ctx, address, hex_bytes):
    """Write bytes to emulated memory."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.post('emulation/memory',
                               json_data={'address': validate_address(address), 'hex': hex_bytes}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('set-breakpoint')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.pass_context
def set_breakpoint(ctx, address):
    """Set an emulation breakpoint."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.post('emulation/breakpoints',
                               json_data={'address': validate_address(address)}))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('clear-breakpoint')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.pass_context
def clear_breakpoint(ctx, address):
    """Clear an emulation breakpoint."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.delete(f'emulation/breakpoints/{validate_address(address)}'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('set-hook')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.option('--action', '-A', required=True, type=click.Choice(["return_const", "skip", "log", "trap"]), help='Hook action')
@click.option('--return-value', '-r', help='Return value (hex, only for return_const)')
@click.pass_context
def set_hook(ctx, address, action, return_value):
    """Set an emulation hook at an address."""
    client = ctx.obj['client']
    try:
        body = {'address': validate_address(address), 'action': action}
        if return_value:
            body['return_value'] = return_value
        _emit(ctx, client.post('emulation/hooks', json_data=body))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('clear-hook')
@click.option('--address', '-a', required=True, help='Address (hex)')
@click.pass_context
def clear_hook(ctx, address):
    """Clear an emulation hook at an address."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.delete(f'emulation/hooks/{validate_address(address)}'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('list-hooks')
@click.pass_context
def list_hooks(ctx):
    """List all registered emulation hooks."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.get('emulation/hooks'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('call')
@click.option('--func', '-f', required=True, help='Function entry address or name')
@click.option('--arg', 'int_args', multiple=True, help='Integer arg (decimal or 0xhex); repeatable')
@click.option('--arg-bytes', 'byte_args', multiple=True,
              help='Pointer arg: hex bytes parked in scratch, pointer passed; repeatable')
@click.option('--convention', type=click.Choice(['sysv', 'ms']), default='sysv')
@click.option('--trace/--no-trace', default=False)
@click.pass_context
def call(ctx, func, int_args, byte_args, convention, trace):
    """Call a function using PCode emulation."""
    client = ctx.obj['client']
    try:
        args = list(int_args)
        args += [{"bytes": validate_address(b)} for b in byte_args]
        body = {'func': func, 'convention': convention, 'trace': trace}
        if args:
            body['args'] = args
        _emit(ctx, client.post('emulation/call', json_data=body))
    except ValueError as e:
        raise click.ClickException(str(e))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@emulation.command('dispose')
@click.pass_context
def dispose(ctx):
    """Dispose the emulation session."""
    client = ctx.obj['client']
    try:
        _emit(ctx, client.delete('emulation'))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
