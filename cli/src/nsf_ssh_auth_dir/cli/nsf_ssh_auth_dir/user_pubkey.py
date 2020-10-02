from typing import Optional

import click

from nsf_ssh_auth_dir.cli.arguments import (
    cli_ssh_user_id_argument,
    ensure_ssh_user_id_or_fallback_or_fail,
    cli_ssh_pubkey_argument,
    ensure_ssh_pubkey_or_fallback_or_fail
)
from nsf_ssh_auth_dir.click.error import CliError
from nsf_ssh_auth_dir.repo_users import (
    SshUsersRepoFileAccessError,
    SshUsersRepoKeyAccessError
)

from nsf_ssh_auth_dir.repo_user_pubkeys import SshUserPubkeysRepoAccessError

from ._ctx import CliCtx, pass_cli_ctx


@click.group()
def pubkey() -> None:
    """Ssh user public key related commands."""
    pass


# TODO: Set alternative file.
@pubkey.command(name="set")
@cli_ssh_user_id_argument()
@cli_ssh_pubkey_argument()
@pass_cli_ctx
def _set(
        ctx: CliCtx,
        ssh_user_id: Optional[str],
        ssh_pubkey: Optional[str]
) -> None:
    """Set a new *ssh public key* for the specified user.

    SSH_PUBKEY: The ssh public key.

        '-': Will read the pubkey from stdin.

        ValidPath: Will read pubkey from the specified file.

        NotAValidPath: Will assume the key was passed as input.

        Unspecified: In case the SSH_USER_ID is not specified,
    will assume the current user and read the ssh key
    directly from '~/.ssh/id_rsa.pub'.

        Otherwise, will attempt to copy it from the clipboard.
    """
    pubkey = ensure_ssh_pubkey_or_fallback_or_fail(ssh_pubkey, ssh_user_id, ctx.user_id)

    user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    try:
        ctx.repo.users[user_id].pubkey_default = pubkey
    except (SshUsersRepoFileAccessError, SshUsersRepoKeyAccessError) as e:
        raise CliError(str(e)) from e


@pubkey.command()
@cli_ssh_user_id_argument()
@pass_cli_ctx
def info(ctx: CliCtx, ssh_user_id: Optional[str]) -> None:
    """Print information about the *ssh public key* for the specified user."""
    ssh_user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    repo = ctx.repo
    try:
        try:
            pk_selected_fn_str = str(
                repo.users[ssh_user_id].pubkeys.selected_filename)
        except SshUserPubkeysRepoAccessError:
            pk_selected_fn_str = "null"
        click.echo(
            f"{ssh_user_id}.pubkey.selected: "
            f"'{pk_selected_fn_str}'"
        )
        try:
            pk_default_fn_str = str(
                repo.users[ssh_user_id].pubkeys.default_filename)
        except SshUserPubkeysRepoAccessError:
            pk_default_fn_str = "null"
        click.echo(
            f"{ssh_user_id}.pubkey.default: "
            f"'{pk_default_fn_str}'"
        )
    except (SshUsersRepoFileAccessError, SshUsersRepoKeyAccessError) as e:
        raise CliError(str(e)) from e


# TODO: Print *default* vs *selected*?
@pubkey.command()
@cli_ssh_user_id_argument()
@pass_cli_ctx
def print(ctx: CliCtx, ssh_user_id: Optional[str]) -> None:
    """Print the current *ssh public key* for the specified user."""
    ssh_user_id = ensure_ssh_user_id_or_fallback_or_fail(
        ssh_user_id, ctx.user_id)

    repo = ctx.repo
    try:
        pk = repo.users[ssh_user_id].pubkey_default
        for l in pk.text_lines:
            click.echo(l.rstrip("\n"))
    except (SshUsersRepoFileAccessError, SshUsersRepoKeyAccessError) as e:
        raise CliError(str(e)) from e
