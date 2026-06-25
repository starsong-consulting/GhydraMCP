"""Dynamic analysis (Unicorn emulation) commands."""

import click

from ..client.exceptions import GhidraError
from ..dynamic.unicorn_engine import StopReason
from ..utils import rich_echo, validate_address


def _make_session(ctx):
    try:
        from ..dynamic.unicorn_engine import UnicornSession
        from ..dynamic.ghidra_provider import make_ghidra_provider
    except ImportError:
        raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")
    client = ctx.obj['client']
    try:
        return UnicornSession(byte_provider=make_ghidra_provider(client))
    except RuntimeError as e:
        if "unicorn not installed" in str(e):
            raise click.ClickException("unicorn not installed; pip install ghydramcp[unicorn]")
        raise   # an unrelated construction failure must not masquerade as a missing dependency


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


@dynamic.command('map')
@click.option('--address', '-a', required=True, help='Region start (hex)')
@click.option('--size', '-n', type=int, required=True, help='Region size in bytes')
@click.pass_context
def map(ctx, address, size):
    """Map a zero-filled scratch region (e.g. a stack) before run/dump."""
    try:
        session = _make_session(ctx)
        addr = int(validate_address(address), 16)
        session.map_bytes(addr, b"\x00" * size)
        click.echo(f"mapped {hex(addr)} +{size}")
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)


@dynamic.command('call')
@click.option('--func', '-f', required=True, help='Function entry address (hex)')
@click.option('--arg', 'int_args', multiple=True, help='Integer arg (decimal or 0xhex); repeatable')
@click.option('--arg-bytes', 'byte_args', multiple=True,
              help='Pointer arg: hex bytes parked in scratch, pointer passed; repeatable')
@click.option('--hook', 'hooks', multiple=True,
              help='address:action[:retval], e.g. 0x401100:return_const:0; repeatable')
@click.option('--convention', type=click.Choice(['sysv', 'ms']), default='sysv')
@click.option('--count', type=int, default=1000000, help='Instruction cap')
@click.pass_context
def call(ctx, func, int_args, byte_args, hooks, convention, count):
    """Call a function (set up the ABI, stub imports via --hook) and print the result.

    Hooks are per-invocation: register them inline with --hook in the same call.
    """
    from ..dynamic.unicorn_engine import Hook, StopReason
    try:
        session = _make_session(ctx)
        # Click cannot interleave two multiple=True options; ints always precede bytes-args.
        args: list = [int(a, 0) for a in int_args]
        args += [{"bytes": validate_address(b)} for b in byte_args]
        for spec in hooks:
            parts = spec.split(":")
            if len(parts) < 2:
                raise click.ClickException(f"bad --hook {spec!r}; want address:action[:retval]")
            addr = int(validate_address(parts[0]), 16)
            action = parts[1]
            retval = int(parts[2], 16) if len(parts) > 2 else None
            session.set_hook(addr, Hook(action=action, return_value=retval))
        out = session.call(int(validate_address(func), 16), args, convention, count=count)
        click.echo(f"return_value={hex(out['return_value'])} "
                   f"stop={out['stop_reason']} convention={out['convention']}")
        if out.get("last_error"):
            click.echo(f"  error: {out['last_error']}")
        if out["stop_reason"] != StopReason.DONE:
            ctx.exit(1)
    except ValueError as e:
        raise click.ClickException(str(e))
    except GhidraError as e:
        rich_echo(ctx.obj['formatter'].format_error(e), err=True)
        ctx.exit(1)
