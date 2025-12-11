"""UI integration commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo


@click.group('ui')
def ui():
    """UI integration commands.

    Commands for interacting with Ghidra's UI state.
    """
    pass


@ui.command('get-current-address')
@click.pass_context
def get_current_address(ctx):
    """Get the address currently selected in Ghidra's UI.

    \b
    Example:
        ghydra ui get-current-address
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('ui/current-address')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@ui.command('get-current-function')
@click.pass_context
def get_current_function(ctx):
    """Get the function currently selected in Ghidra's UI.

    \b
    Example:
        ghydra ui get-current-function
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('ui/current-function')
        output = formatter.format_function_info(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
