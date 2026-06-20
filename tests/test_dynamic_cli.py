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
