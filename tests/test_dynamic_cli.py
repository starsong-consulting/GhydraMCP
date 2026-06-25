import pytest

pytest.importorskip("unicorn")
from click.testing import CliRunner

from ghydra.cli.dynamic import dump, run as dyn_run
from ghydra.formatters import TableFormatter
from ghydra.client.exceptions import GhidraConnectionError


class RaisingClient:
    """Every memory fetch fails -> the first code-page fetch faults the run."""
    def get(self, endpoint, params=None):
        raise GhidraConnectionError("ghidra unreachable")


def _obj():
    return {"client": RaisingClient(),
            "formatter": TableFormatter(use_colors=False),
            "config": None}


def test_dump_aborts_and_prints_no_hex_on_faulted_run():
    result = CliRunner().invoke(
        dump,
        ["--start", "0x140075000", "--until", "0x140075002",
         "--address", "0x140075000", "--length", "16"],
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert result.stdout.strip() == ""               # no hex dump on stdout
    assert "LAZY_FETCH_FAILED" in result.stderr


def test_run_reports_stop_reason_and_error():
    result = CliRunner().invoke(
        dyn_run,
        ["--start", "0x140075000", "--until", "0x140075002"],
        obj=_obj(),
    )
    assert "LAZY_FETCH_FAILED" in result.output
    assert result.exit_code != 0          # a faulted run is a non-success at the shell level


def test_map_command_reports_mapped_region():
    from ghydra.cli.dynamic import map as dyn_map

    class OkClient:
        def get(self, endpoint, params=None):
            raise AssertionError("map must not hit Ghidra")

    result = CliRunner().invoke(
        dyn_map,
        ["--address", "0x140070000", "--size", "8192"],
        obj={"client": OkClient(), "formatter": TableFormatter(use_colors=False), "config": None},
    )
    assert result.exit_code == 0
    assert "0x140070000" in result.output


def test_call_rejects_float_arg():
    from ghydra.cli.dynamic import call as dyn_call
    result = CliRunner().invoke(
        dyn_call,
        ["--func", "0x140075000", "--arg", "1.5"],     # int("1.5", 0) -> ValueError
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert "1.5" in result.output or "invalid" in result.output.lower()


def test_call_hook_parsing_rejects_bad_action():
    from ghydra.cli.dynamic import call as dyn_call
    result = CliRunner().invoke(
        dyn_call,
        ["--func", "0x140075000", "--hook", "0x401100:explode"],
        obj=_obj(),
    )
    assert result.exit_code != 0
    assert "action" in result.output.lower() or "explode" in result.output.lower()


def test_call_arg_bytes_leading_zero_not_corrupted():
    from ghydra.cli.dynamic import call as dyn_call
    result = CliRunner().invoke(
        dyn_call,
        ["--func", "0x140075000", "--arg-bytes", "0x0abc"],
        obj=_obj(),
    )
    # Fixed: "0abc" parses cleanly -> run reaches the engine and faults fetching
    #   the function bytes (RaisingClient) -> stop_reason LAZY_FETCH_FAILED.
    # Old (buggy): lstrip('0x') -> "abc" (odd) -> bytes.fromhex raises before the
    #   run -> a hex/ClickException error, NOT LAZY_FETCH_FAILED.
    assert result.exit_code != 0
    assert "LAZY_FETCH_FAILED" in result.output
