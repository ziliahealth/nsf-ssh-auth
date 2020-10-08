from typing import List

import click

from nsf_ssh_auth_dir.cli.arguments import cli_ssh_group_id_argument
from nsf_ssh_auth_dir.cli.options import (
    cli_device_state_always_flag,
    cli_device_state_on_option,
    cli_device_user_from_any_flag,
    cli_device_user_from_option,
    cli_device_user_to_all_flag,
    cli_device_user_to_option,
    cli_force_flag
)
from nsf_ssh_auth_dir.click.error import CliError, echo_warning
from nsf_ssh_auth_dir.repo_auth_device_users import (
    SshAuthRepoGroupAlreadyAuthorizedError,
    SshAuthRepoInvalidGroupError,
    SshAuthRepoKeyAccessError,
)
from nsf_ssh_auth_dir.repo_groups import (
    SshGroupsRepoAccessError,
    SshGroupsRepoDuplicateError,
)

from ._auth_tools import (
    deauthorize_group_from_all_auth_device_users,
    select_auth_device_users_where,
)
from ._ctx import CliCtx, pass_cli_ctx
from .group_member import member


@click.group()
def group() -> None:
    """Ssh groups related commands."""
    pass


@group.command()
@pass_cli_ctx
def ls(ctx: CliCtx) -> None:
    """List existing *ssh group*."""
    try:
        for g_name in ctx.repo.groups.names:
            click.echo(g_name)
    except SshGroupsRepoAccessError as e:
        raise CliError(str(e)) from e


@group.command()
@cli_ssh_group_id_argument()
@cli_force_flag()
@pass_cli_ctx
def add(
        ctx: CliCtx,
        ssh_group_id: str,
        force: bool
) -> None:
    """Add a new *ssh group*."""
    try:
        ctx.repo.groups.add(
            ssh_group_id, exist_ok=force)
    except SshGroupsRepoDuplicateError as e:
        raise CliError(str(e)) from e


@group.command()
@cli_ssh_group_id_argument()
@cli_force_flag()
@pass_cli_ctx
def rm(
        ctx: CliCtx,
        ssh_group_id: str,
        force: bool
) -> None:
    """Remove and existing *ssh group*."""
    deauthorize_group_from_all_auth_device_users(ctx.repo, ssh_group_id)

    try:
        ctx.repo.groups.rm(ssh_group_id)
    except SshGroupsRepoAccessError as e:
        if not force:
            raise CliError(str(e)) from e


@group.command()
@cli_ssh_group_id_argument()
@cli_device_user_to_option()
@cli_device_user_to_all_flag()
@cli_device_state_on_option()
@cli_device_state_always_flag()
@cli_force_flag()
@pass_cli_ctx
def authorize(
        ctx: CliCtx,
        ssh_group_id: str,
        device_user_ids: List[str],
        device_user_all: bool,
        device_state_ons: List[str],
        device_state_always: bool,
        force: bool
) -> None:
    """Authorize a *ssh group* to *device user(s)*."""
    dus = select_auth_device_users_where(
        ctx.repo,
        device_user_ids, device_user_all,
        device_state_ons, device_state_always)

    try:
        for du in dus:
            try:
                du.authorize_group_by_id(
                    ssh_group_id, force=force)
            except SshAuthRepoGroupAlreadyAuthorizedError:
                echo_warning(
                    f"Group '{ssh_group_id}' already authorized to *device user* "
                    f"'{du.formatted_name}'. on '{du.formatted_state_name}' state. "
                    "Skipping.")
            except SshAuthRepoInvalidGroupError as e:
                raise CliError(str(e)) from e
    except SshGroupsRepoAccessError as e:
        raise CliError(str(e)) from e


@group.command()
@cli_ssh_group_id_argument()
@cli_device_user_from_option()
@cli_device_user_from_any_flag()
@cli_device_state_on_option()
@cli_device_state_always_flag()
@cli_force_flag()
@pass_cli_ctx
def deauthorize(
        ctx: CliCtx,
        ssh_group_id: str,
        device_user_ids: List[str],
        device_user_all: bool,
        device_state_ons: List[str],
        device_state_always: bool,
        force: bool
) -> None:
    """De-authorize a *ssh group* from *device user(s)*."""
    if (not device_user_ids
            and not device_user_all
            and not device_state_ons
            and not device_state_always):
        deauthorize_group_from_all_auth_device_users(ctx.repo, ssh_group_id)
        return

    dus = select_auth_device_users_where(
        ctx.repo,
        device_user_ids, device_user_all,
        device_state_ons, device_state_always)

    for du in dus:
        try:
            du.deauthorize_group_by_id(
                ssh_group_id, force=force)
        except SshAuthRepoKeyAccessError:
            echo_warning(
                f"Group '{ssh_group_id}' already not authorized to *device user* "
                f"'{du.formatted_name}' on '{du.formatted_state_name}' state. "
                "Skipping.")
        except SshAuthRepoInvalidGroupError as e:
            raise CliError(str(e)) from e


group.add_command(member)
