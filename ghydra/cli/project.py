"""Project management commands."""

import click

from ..client.exceptions import GhidraError
from ..utils import should_page, page_output, rich_echo


@click.group('project')
def project():
    """Project management commands.

    Commands for managing Ghidra projects and files.
    """
    pass


@project.command('info')
@click.pass_context
def info(ctx):
    """Get information about the currently open Ghidra project.

    \b
    Example:
        ghydra project info
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('project')
        output = formatter.format_project_info(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('list-files')
@click.option('--folder', default='/', help='Folder path (default: /)')
@click.option('--recursive/--no-recursive', default=True, help='Recursively list all files')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_files(ctx, folder, recursive, offset, limit):
    """List files in the current Ghidra project.

    \b
    Examples:
        ghydra project list-files
        ghydra project list-files --folder "/malware"
        ghydra project list-files --no-recursive
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']
    config = ctx.obj['config']

    try:
        params = {
            'folder': folder,
            'recursive': str(recursive).lower(),
            'offset': offset,
            'limit': limit
        }

        response = client.get('project/files', params=params)
        output = formatter.format_simple_result(response)

        if should_page(config, ctx.obj['output_json']):
            page_output(output, use_pager=config.page_output)
        else:
            click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('open-file')
@click.option('--path', required=True, help='Path to file (e.g., "/malware.exe")')
@click.pass_context
def open_file(ctx, path):
    """Open a file from the project in CodeBrowser.

    This opens the file in a new CodeBrowser window (new instance).
    Use 'ghydra instances discover' to find the new instance.

    \b
    Example:
        ghydra project open-file --path "/malware.exe"
    """
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        data = {'path': path}

        response = client.post('project/open', json_data=data)
        output = formatter.format_simple_result(response)
        click.echo(output)

        click.echo("\nTip: Run 'ghydra instances discover' to find the new instance", err=True)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('list-projects')
@click.pass_context
def list_projects(ctx):
    """List projects visible to the plugin."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get('projects')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('get-project')
@click.option('--name', required=True, help='Project name')
@click.pass_context
def get_project(ctx, name):
    """Get project details by name."""
    from urllib.parse import quote

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        response = client.get(f'projects/{quote(name)}')
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('list-programs')
@click.option('--project-name', help='Optional project name filter')
@click.option('--offset', type=int, default=0, help='Pagination offset')
@click.option('--limit', type=int, default=100, help='Maximum results to return')
@click.pass_context
def list_programs(ctx, project_name, offset, limit):
    """List programs."""
    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        params = {'offset': offset, 'limit': limit}
        if project_name:
            params['project'] = project_name

        response = client.get('programs', params=params)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('get-program')
@click.option('--program-id', default='current', help='Program ID or "current"')
@click.pass_context
def get_program(ctx, program_id):
    """Get program details by ID or current."""
    from urllib.parse import quote

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        if program_id == 'current':
            endpoint = 'programs/current'
        else:
            endpoint = f'programs/{quote(program_id, safe="")}'

        response = client.get(endpoint)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)


@project.command('delete-program')
@click.option('--program-id', default='current', help='Program ID or "current"')
@click.pass_context
def delete_program(ctx, program_id):
    """Delete/close program by ID or current."""
    from urllib.parse import quote

    client = ctx.obj['client']
    formatter = ctx.obj['formatter']

    try:
        if program_id == 'current':
            endpoint = 'programs/current'
        else:
            endpoint = f'programs/{quote(program_id, safe="")}'

        response = client.delete(endpoint)
        output = formatter.format_simple_result(response)
        click.echo(output)

    except GhidraError as e:
        error_output = formatter.format_error(e)
        rich_echo(error_output, err=True)
        ctx.exit(1)
