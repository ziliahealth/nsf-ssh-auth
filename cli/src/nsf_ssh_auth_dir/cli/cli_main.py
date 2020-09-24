import click

from .user import user
from .group import group
from .git import git
from ._ctx import CliCtx, pass_init_ctx, init_cli_ctx
from ._log import setup_verbose


@click.group()
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Ssh authorization tool for nixos-secure-factory.

    All commands operate on the current *ssh auth dir* which
    by default correspond to the *current working directory*.
    """

    init_cli_ctx(ctx, CliCtx.mk_default())
    setup_verbose(1)


@cli.command()
@pass_init_ctx
def info(init_ctx: CliCtx) -> None:
    """Print information about the current *ssh auth dir*."""

    print(f"cwd: '{init_ctx.cwd}'")
    if init_ctx.user_id is not None:
        print(f"user-id: '{init_ctx.user_id}'")


cli.add_command(user)
cli.add_command(group)
cli.add_command(git)


def run_cli() -> None:
    return cli()


if __name__ == "__main__":
    run_cli()
