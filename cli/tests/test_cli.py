# import logging
import click
from pathlib import Path
from _pytest.logging import LogCaptureFixture

from nsf_ssh_auth_dir.cli import cli, CliCtx, init_cli_ctx
from test_lib.click import invoke_cli


def test_help(caplog: LogCaptureFixture) -> None:
    result = invoke_cli(caplog, cli, ['--help'])
    assert 0 == result.exit_code


def test_info(caplog: LogCaptureFixture) -> None:
    result = invoke_cli(caplog, cli, ['info'])
    assert 0 == result.exit_code


def test_info_w_custom_cli_ctx(caplog: LogCaptureFixture) -> None:
    init_ctx = CliCtx(cwd=Path("/my/path"), user_id="my_user_id")

    @click.group(cls=click.CommandCollection, sources=[cli])
    @click.pass_context
    def cli_parameterized(ctx: click.Context):
        init_cli_ctx(ctx, init_ctx)

    result = invoke_cli(caplog, cli_parameterized, ['info'])
    # assert 0 == result.exit_code
    # logging.info(f"stdout:\n{result.output}")
    assert str(init_ctx.cwd) in result.output
    assert init_ctx.user_id is not None
    assert init_ctx.user_id in result.output
