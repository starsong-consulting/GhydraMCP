"""Dynamic analysis (Unicorn emulation) commands."""

import click

from ..client.exceptions import GhidraError
from ..dynamic.unicorn_engine import StopReason
from ..utils import rich_echo, validate_address


def _make_session(ctx):
    try:
        from ..dynamic.unicorn_engine import UnicornSession
        from ..dynamic.ghidra_provider import make_ghidra_provider
    except (ImportError, RuntimeError):
        raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")
    client = ctx.obj['client']
    try:
        return UnicornSession(byte_provider=make_ghidra_provider(client))
    except RuntimeError:
        raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")


@click.group('dynamic')
def dynamic():
    """Unicorn-based emulation (bytes pulled lazily from Ghidra)."""
    pass


@dynamic.command('run')
@click.option('--start', '-s', required=True, help='Start address (hex)')
@click.option('--until', '-u', required=True, help='Stop address (hex)')
@click.option('--count', type=int, default=100000, help='Instruction cap')
@click.option('--trace/--no-trace', default=False)
@click.pass_context
def run(ctx, start, until, count, trace):
    """Emulate start..until and print final register state."""
    try:
        session = _make_session(ctx)
        begin = int(validate_address(start), 16)
        session.set_register("RIP", begin)
        state = session.run(begin=begin, until=int(validate_address(until), 16),
                            count=count, trace=trace)
        click.echo(f"pc={hex(state['pc'])} steps={state['steps']} "
                   f"stop={state['stop_reason']}")
        for name, value in state["registers"].items():
            click.echo(f"  {name}={hex(value)}")
        if state.get("last_error"):
            click.echo(f"  error: {state['last_error']}")
        if trace:
            suffix = " (truncated)" if state.get("trace_truncated") else ""
            click.echo(f"  trace: {len(state['trace'])} instrs, "
                       f"{len(state['mem_writes'])} writes{suffix}")
        if state["stop_reason"] != StopReason.DONE:
            ctx.exit(1)   # any non-DONE stop is a non-success (matches dump + bridge)
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@dynamic.command('dump')
@click.option('--start', '-s', required=True, help='Entry address (hex)')
@click.option('--until', '-u', required=True, help='Stop address (hex)')
@click.option('--address', '-a', required=True, help='Address to dump after run (hex)')
@click.option('--length', '-l', type=int, default=256, help='Bytes to dump')
@click.option('--count', type=int, default=1000000, help='Instruction cap')
@click.pass_context
def dump(ctx, start, until, address, length, count):
    """Run an unpacker (start..until), then dump emulated memory (e.g. .xd)."""
    try:
        session = _make_session(ctx)
        begin = int(validate_address(start), 16)
        session.set_register("RIP", begin)
        state = session.run(begin=begin, until=int(validate_address(until), 16), count=count)
        if state["stop_reason"] != StopReason.DONE:
            click.echo(
                f"emulation did not complete: stop={state['stop_reason']} "
                f"{state.get('last_error') or ''}".rstrip(),
                err=True,
            )
            ctx.exit(1)
        data = session.read_memory(int(validate_address(address), 16), length)
        click.echo(data.hex())
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
