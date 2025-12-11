"""Comment management commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import rich_echo


@click.group('comments')
def comments():
    """Comment management commands.

    Commands for adding and managing comments in the binary.
    """
    pass


@comments.command('set')
@click.option('--address', '-a', required=True, help='Memory address (hex)')
@click.option('--comment', required=True, help='Comment text (empty string removes comment)')
@click.option('--comment-type', type=click.Choice(['plate', 'pre', 'post', 'eol', 'repeatable']), default='plate', help='Comment type')
@click.pass_context
def set_comment(ctx, address, comment, comment_type):
    """Set a comment at specified address.

    \b
    Comment types:
        plate: Large comment above code block
        pre: Comment immediately before instruction
        post: Comment immediately after instruction
        eol: End-of-line comment
        repeatable: Repeatable comment

    \b
    Examples:
        ghydra comments set --address 0x401000 --comment "This is the entry point"
        ghydra comments set --address 0x401000 --comment "Loop counter" --comment-type eol
        ghydra comments set --address 0x401000 --comment ""  # Remove comment
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {
            'comment': comment,
            'type': comment_type
        }

        response = client.post(f'comments/{address.lstrip("0x")}', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
