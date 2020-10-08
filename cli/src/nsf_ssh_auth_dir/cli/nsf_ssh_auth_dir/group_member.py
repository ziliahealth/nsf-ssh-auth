from typing import Optional

import click

from nsf_ssh_auth_dir.cli.arguments import (
    cli_ssh_group_id_argument,
    cli_ssh_user_id_argument,
    cli_ssh_group_member_id_argument,
    ensure_ssh_user_id_or_fallback_or_fail,
)
from nsf_ssh_auth_dir.cli.options import cli_force_flag
from nsf_ssh_auth_dir.repo_groups import (
    SshGroupsRepoAccessError,
    SshGroupsRepoDuplicateError,
)
from nsf_ssh_auth_dir.click.error import CliError

from ._ctx import CliCtx, pass_cli_ctx


@click.group()
def member() -> None:
    """Ssh group member related commands."""
    pass


@member.command()
@cli_ssh_group_id_argument()
@pass_cli_ctx
def ls(ctx: CliCtx, ssh_group_id: str) -> None:
    """List members for specified *ssh group*."""
    try:
        for m_name in ctx.repo.groups[ssh_group_id].members_names:
            click.echo(m_name)
    except SshGroupsRepoAccessError as e:
        raise CliError(str(e)) from e


@member.command()
@cli_ssh_group_id_argument()
@cli_ssh_user_id_argument()
@cli_force_flag()
@pass_cli_ctx
def add(
        ctx: CliCtx,
        ssh_group_id: str,
        ssh_user_id: Optional[str],
        force: bool
) -> None:
    """Add a *ssh user* to a *ssh group*."""
    user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    try:
        ctx.repo.groups[ssh_group_id].add_member_by_id(
            user_id, force=force)
    except (SshGroupsRepoAccessError, SshGroupsRepoDuplicateError) as e:
        raise CliError(str(e)) from e


@member.command()
@cli_ssh_group_id_argument()
@cli_ssh_group_member_id_argument()
@cli_force_flag()
@pass_cli_ctx
def rm(
        ctx: CliCtx,
        ssh_group_id: str,
        ssh_group_member_id: str,
        force: bool
) -> None:
    """Remove a *ssh user* from a *ssh group*."""
    try:
        ctx.repo.groups[ssh_group_id].rm_member_by_id(
            ssh_group_member_id, force=force)
    except SshGroupsRepoAccessError as e:
        raise CliError(str(e)) from e
