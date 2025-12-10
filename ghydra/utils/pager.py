"""Output paging utilities."""

import os
import subprocess
import sys
import shutil


def page_output(text: str, use_pager: bool = True):
    """Display text using a pager if available and enabled.

    Respects the $PAGER environment variable, falls back to 'less',
    and outputs directly if no pager is available.

    Args:
        text: Text to display
        use_pager: Enable paging (default: True)
    """
    if not use_pager or not sys.stdout.isatty():
        # Direct output if paging disabled or not in a TTY
        print(text)
        return

    # Get pager command
    pager = os.environ.get('PAGER')

    if not pager:
        # Try to find 'less' in PATH
        pager = shutil.which('less')

    if not pager:
        # Try to find 'more' in PATH
        pager = shutil.which('more')

    if not pager:
        # No pager available, output directly
        print(text)
        return

    # Use the pager
    try:
        # Set up less with nice defaults
        env = os.environ.copy()
        if 'less' in pager.lower():
            # -R: allow ANSI color codes
            # -F: quit if output fits on one screen
            # -X: don't clear screen on exit
            if 'LESS' not in env:
                env['LESS'] = '-RFX'

        # Pipe output to pager
        proc = subprocess.Popen(
            pager,
            stdin=subprocess.PIPE,
            env=env,
            shell=True
        )
        proc.communicate(input=text.encode('utf-8'))
    except (IOError, OSError, KeyboardInterrupt):
        # If paging fails, just print directly
        print(text)


def should_page(config, output_json: bool) -> bool:
    """Determine if output should be paged.

    Args:
        config: GhidraConfig instance
        output_json: Whether output is JSON

    Returns:
        True if paging should be used
    """
    # Don't page JSON output
    if output_json:
        return False

    # Check config setting
    return config.page_output
