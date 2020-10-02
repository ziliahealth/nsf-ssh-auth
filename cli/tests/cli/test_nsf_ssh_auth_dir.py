# import logging
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
import click
from _pytest.logging import LogCaptureFixture

from nsf_ssh_auth_dir.cli.nsf_ssh_auth_dir import (
    CliCtxDbInterface,
    cli,
    init_cli_ctx,
    mk_cli_context_settings,
)
from test_lib.click import invoke_cli


def test_help(caplog: LogCaptureFixture) -> None:
    result = invoke_cli(caplog, cli, ['--help'])
    assert 0 == result.exit_code


def test_info(caplog: LogCaptureFixture) -> None:
    result = invoke_cli(caplog, cli, ['info'])
    assert 0 == result.exit_code


def test_info_w_custom_cli_ctx(caplog: LogCaptureFixture) -> None:
    @dataclass
    class CtxParams:
        cwd: Path
        user_id: Optional[str]

    ctx_params = CtxParams(
        cwd=Path("/my/path"),
        user_id="my_user_id"
    )

    class CliCtxDb(CliCtxDbInterface):
        def __init__(self, ctx: click.Context) -> None:
            pass

    @click.group(
        cls=click.CommandCollection,
        sources=[cli],
        context_settings=mk_cli_context_settings(
            mk_db=CliCtxDb
        )
    )
    @click.pass_context
    def cli_parameterized(ctx: click.Context):
        init_cli_ctx(
            ctx,
            repo=ctx_params.cwd,
            user_id=ctx_params.user_id
        )

    result = invoke_cli(caplog, cli_parameterized, ['info'])
    # assert 0 == result.exit_code
    # logging.info(f"stdout:\n{result.output}")
    assert str(ctx_params.cwd) in result.output
    assert ctx_params.user_id is not None
    assert ctx_params.user_id in result.output
