from typing import List, Optional

import click

from nsf_ssh_auth_dir.cli.arguments import (
    cli_ssh_pubkey_argument,
    cli_ssh_user_id_argument,
    ensure_ssh_pubkey_or_fallback_or_fail,
    ensure_ssh_user_id_or_fallback_or_fail,
)
from nsf_ssh_auth_dir.cli.options import (
    cli_device_state_always_flag,
    cli_device_state_on_option,
    cli_device_user_from_any_flag,
    cli_device_user_from_option,
    cli_device_user_to_all_flag,
    cli_device_user_to_option,
    cli_user_groups_option,
)
from nsf_ssh_auth_dir.click.error import CliError, echo_warning
from nsf_ssh_auth_dir.repo_auth_device_users import (
    SshAuthRepoInvalidUserError,
    SshAuthRepoKeyAccessError,
    SshAuthRepoUserAlreadyAuthorizedError,
)
from nsf_ssh_auth_dir.repo_users import (
    SshUsersRepoDuplicateError,
    SshUsersRepoFileAccessError,
    SshUsersRepoKeyAccessError,
)

from ._auth_tools import (
    deauthorize_user_from_all_auth_device_users,
    select_auth_device_users_where,
)
from ._ctx import CliCtx, pass_cli_ctx
from ._group_tools import add_user_to_groups, rm_user_from_all_groups
from .user_pubkey import pubkey


@click.group()
def user() -> None:
    """Ssh users related commands."""
    pass


@user.command()
@pass_cli_ctx
def ls(ctx: CliCtx) -> None:
    """List existing *ssh user*."""
    repo = ctx.repo

    try:
        for uname in repo.users.names:
            click.echo(uname)
    except SshUsersRepoFileAccessError as e:
        raise CliError(str(e)) from e


@user.command()
@cli_ssh_user_id_argument()
@cli_ssh_pubkey_argument()
@cli_user_groups_option()
@pass_cli_ctx
def add(
        ctx: CliCtx,
        ssh_user_id: Optional[str],
        ssh_pubkey: Optional[str],
        user_group_ids: List[str]
) -> None:
    """Add a new *ssh user*.

    SSH_USER_ID: The textual id to give to this user.

        Ideally, use character that can be
    used in filesystem / url. No whitespaces either.

    SSH_PUBKEY: The ssh public key.

        '-': Will read the pubkey from stdin.

        ValidPath: Will read pubkey from the specified file.

        NotAValidPath: Will assume the key was passed as input.

        Unspecified: In case the SSH_USER_ID is not specified,
    will assume the current user and read the ssh key
    directly from '~/.ssh/id_rsa.pub'.

        Otherwise, will attempt to copy it from the clipboard.

    TODO: -f/--force: Prevent the user already exists error
    and allow for missing group creation.
    """
    user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    pubkey = ensure_ssh_pubkey_or_fallback_or_fail(
        ssh_pubkey, ssh_user_id, ctx.user_id)

    try:
        ctx.repo.users.add(user_id, pubkey)
    except SshUsersRepoDuplicateError as e:
        raise CliError(str(e)) from e

    add_user_to_groups(ctx.repo, user_id, user_group_ids)


@user.command()
@cli_ssh_user_id_argument()
@pass_cli_ctx
def rm(ctx: CliCtx, ssh_user_id: Optional[str]) -> None:
    """Remove an existing *ssh user*."""
    user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    deauthorize_user_from_all_auth_device_users(ctx.repo, user_id)
    rm_user_from_all_groups(ctx.repo, user_id)

    try:
        ctx.repo.users.rm(user_id)
    except (SshUsersRepoFileAccessError, SshUsersRepoKeyAccessError) as e:
        raise CliError(str(e)) from e


@user.command()
@cli_ssh_user_id_argument()
@cli_device_user_to_option()
@cli_device_user_to_all_flag()
@cli_device_state_on_option()
@cli_device_state_always_flag()
@pass_cli_ctx
def authorize(
        ctx: CliCtx,
        ssh_user_id: Optional[str],
        device_user_ids: List[str],
        device_user_all: bool,
        device_state_ons: List[str],
        device_state_always: bool
) -> None:
    """Authorize a single *ssh user* to *device user(s)*."""
    user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    dus = select_auth_device_users_where(
        ctx.repo,
        device_user_ids, device_user_all,
        device_state_ons, device_state_always)

    for du in dus:
        try:
            du.authorize_user_by_id(user_id)
        except SshAuthRepoUserAlreadyAuthorizedError:
            echo_warning(
                f"User '{user_id}' already authorized to *device user* "
                f"'{du.formatted_name}'. on '{du.formatted_state_name}' state. "
                "Skipping.")
        except SshAuthRepoInvalidUserError as e:
            raise CliError(str(e)) from e


@user.command()
@cli_ssh_user_id_argument()
@cli_device_user_from_option()
@cli_device_user_from_any_flag()
@cli_device_state_on_option()
@cli_device_state_always_flag()
@pass_cli_ctx
def deauthorize(
        ctx: CliCtx,
        ssh_user_id: Optional[str],
        device_user_ids: List[str],
        device_user_all: bool,
        device_state_ons: List[str],
        device_state_always: bool
) -> None:
    """De-authorize a single *ssh user* from *device user(s)*."""
    user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    if (not device_user_ids
            and not device_user_all
            and not device_state_ons
            and not device_state_always):
        deauthorize_user_from_all_auth_device_users(ctx.repo, user_id)
        return

    dus = select_auth_device_users_where(
        ctx.repo,
        device_user_ids, device_user_all,
        device_state_ons, device_state_always)

    for du in dus:
        try:
            du.deauthorize_user_by_id(user_id)
        except SshAuthRepoKeyAccessError:
            echo_warning(
                f"User '{user_id}' already not authorized to *device user* "
                f"'{du.formatted_name}' on '{du.formatted_state_name}' state. "
                "Skipping.")
        except SshAuthRepoInvalidUserError as e:
            raise CliError(str(e)) from e


user.add_command(pubkey)
