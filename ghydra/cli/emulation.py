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
