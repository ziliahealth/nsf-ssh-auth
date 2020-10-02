from pathlib import Path

import click
from typing import Optional

from nsf_ssh_auth_dir.cli.log import setup_verbose

from ._ctx import (CliCtx, CliCtxDbInterface, init_cli_ctx,
                   mk_cli_context_settings, pass_cli_ctx)
from .git import git
from .group import group
from .user import user


class CliCtxDb(CliCtxDbInterface):
    def __init__(self, ctx: click.Context) -> None:
        pass


@click.group(
    context_settings=mk_cli_context_settings(
        mk_db=CliCtxDb
    )
)
@click.option(
    "--user", "-u", "user_id",
    type=str,
    default=None,
    help=(
        "The id of the default user operation will "
        "fallback to if not provided otherwise."),
    envvar='NSF_CLI_DEFAULT_USER_ID',
)
@click.option(
    "--cwd", "-C", "cwd_str",
    default=None,
    type=click.Path(
        exists=True, dir_okay=True, file_okay=False,
        writable=True, readable=True
    ),
    help=(
        "Current working directory for this cli."
        "Effectively sets the root ssh auth directory."
    )
)
@click.pass_context
def cli(ctx: click.Context, user_id: Optional[str], cwd_str: Optional[str]) -> None:
    """Ssh authorization tool for nixos-secure-factory.

    All commands operate on the current *ssh auth dir* which
    by default correspond to the *current working directory*.
    """

    if cwd_str is None:
        cwd = Path.cwd()
    else:
        cwd = Path(cwd_str)
        if not cwd.is_absolute():
            cwd = Path.cwd().joinpath(cwd)

    init_cli_ctx(
        ctx,
        repo=cwd,
        user_id=user_id
    )
    setup_verbose(1)


@cli.command()
@pass_cli_ctx
def info(ctx: CliCtx) -> None:
    """Print information about the current *ssh auth dir*."""

    print(f"cwd: '{ctx.repo.dir}'")
    if ctx.user_id is not None:
        print(f"user-id: '{ctx.user_id}'")


cli.add_command(user)
cli.add_command(group)
cli.add_command(git)


def run_cli() -> None:
    return cli()


if __name__ == "__main__":
    run_cli()
