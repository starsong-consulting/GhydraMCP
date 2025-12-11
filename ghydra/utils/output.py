"""Output utilities for Rich markup rendering."""

import sys
from rich.console import Console


def rich_echo(message: str, err: bool = False, markup: bool = True) -> None:
    """Echo a message with Rich markup support.

    This function renders Rich markup tags like [red], [cyan], etc.
    before outputting to the console, replacing click.echo() for
    formatted output.

    Args:
        message: Message to print (may contain Rich markup)
        err: If True, print to stderr instead of stdout
        markup: If True, parse Rich markup tags (default: True)
    """
    file = sys.stderr if err else sys.stdout
    console = Console(file=file, markup=markup)
    console.print(message, markup=markup, highlight=False)
