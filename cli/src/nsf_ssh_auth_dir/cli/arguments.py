import click
from typing import Any, Optional, List
from pathlib import Path
from nsf_ssh_auth_dir.click.error import CliUsageError
from nsf_ssh_auth_dir.types_pubkey import SshPubKey
from nsf_ssh_auth_dir.file_pubkey import load_user_home_ssh_pubkey


def cli_ssh_user_id_argument() -> Any:
    """An argument to specify the ssh user id.

    See companion `ensure_ssh_user_id_or_fallback_or_fail`
    to get a final value.
    """
    return click.argument(
        "ssh_user_id",
        type=str,
        required=False,
        default=None,
        envvar='NSF_CLI_SSH_USER_ID',
        # autocompletion=list_ac_available_user_id
    )


def ensure_ssh_user_id_or_fallback_or_fail(
        id: Optional[str], fallback_id: Optional[str]) -> str:
    if id is not None:
        return id

    if fallback_id is not None:
        return fallback_id

    raise CliUsageError("Missing argument \"SSH_USER_ID\".")


def cli_ssh_group_id_argument() -> Any:
    """An argument to specify the ssh group id.
    """
    return click.argument(
        "ssh_group_id",
        type=str,
        required=True,
        envvar='NSF_CLI_SSH_GROUP_ID',
        # autocompletion=list_ac_available_user_id
    )


def cli_ssh_pubkey_argument() -> Any:
    """An option to specify a user id.

    See companion `ensure_ssh_pubkey_or_fallback_or_fail` to get
    a final value.
    """
    return click.argument(
        "ssh_pubkey",
        type=str,
        required=False,
        default=None,
        # autocompletion=list_ac_available_user_id
    )


def _is_valid_ssh_pubkey_lines(pk_lines: List[str]) -> bool:
    if not pk_lines:
        return False

    ln0_split = pk_lines[0].split(maxsplit=1)
    if not ln0_split:
        return False

    if not 2 <= len(ln0_split):
        return False

    # TODO: Use `ssh-keygen` instead or once summary checks were performed.
    # See <https://stackoverflow.com/questions/16336169/sanity-check-ssh-public-key>

    key_type = ln0_split[0]

    # return key_type in ["ssh-rsa"]
    return key_type.startswith("ssh-")


def _mk_valid_ssh_pubkey_from_lines(pk_lines: List[str]) -> SshPubKey:
    if not _is_valid_ssh_pubkey_lines(pk_lines):
        raise CliUsageError(
            "No valid ssh key provided trough stdin or via "
            "the \"SSH_PUBKEY\" argument.")

    return SshPubKey(pk_lines)


def ensure_ssh_pubkey_or_fallback_or_fail(
        ssh_pubkey: Optional[str],
        ssh_user_id: Optional[str] = None,
        default_user_id: Optional[str] = None) -> SshPubKey:
    # IMPROVEMENT IDEA:
    # A flag to enable user prompting for validation of the key.

    if (ssh_pubkey is None
            and ssh_user_id is None
            and default_user_id is not None):
        return load_user_home_ssh_pubkey()

    if "-" == ssh_pubkey:
        # When key argument is not provided, read its value from stdin.
        stdin_text = click.get_text_stream('stdin').read()
        lines = stdin_text.splitlines(keepends=True)
        return _mk_valid_ssh_pubkey_from_lines(lines)

    if ssh_pubkey is not None:
        pk_fn = Path(ssh_pubkey).expanduser()
        if pk_fn.exists():
            with open(pk_fn) as pk_f:
                return _mk_valid_ssh_pubkey_from_lines(
                    list(pk_f))

        lines = ssh_pubkey.splitlines(keepends=True)
        return _mk_valid_ssh_pubkey_from_lines(lines)

    # TODO: Attempt the clipboard.
    # See <https://pypi.org/project/clipboard/>
    # or <https://pypi.org/project/pyperclip/>.

    raise CliUsageError(
        "No valid \"SSH_PUBKEY\" provided / found either "
        "implicitely or explicitely.")


def cli_ssh_group_member_id_argument() -> Any:
    """An argument to specify the ssh group member id.

    This is effectively the id of a user that is
    part of the group.
    """
    return click.argument(
        "ssh_group_member_id",
        type=str,
        required=True,
        envvar='NSF_CLI_SSH_GROUP_MEMBER_ID_ID',
        # autocompletion=list_ac_available_user_id
    )
