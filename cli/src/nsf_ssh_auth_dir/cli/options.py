import click
from typing import Any


def cli_force_flag() -> Any:
    return click.option(
        "--force", "-f", "force",
        is_flag=True,
        default=False,
        help=(
            "Allow one to force some operations to proceed without "
            "error.\n\n"
            "Sometimes it might be used to have the operation "
            "not error out when (add a user when it already exists).\n\n"
            "Other use case is to tell the cli that you know what you"
            "are doing: proceed with authorization even tough the "
            "specified user / group does not exists."),
        # autocompletion=list_ac_available_device_user_ids
    )


def cli_user_groups_option() -> Any:
    return click.option(
        "--group", "-g", "user_group_ids",
        type=str,
        multiple=True,
        help=(
            "The identifier of a group to which to user is to "
            "be added as member.\n"
            "Note that the specified group will be created if "
            "it does not exists."),
        envvar='NSF_CLI_SSH_USER_GROUP_ID',
        # autocompletion=list_ac_available_device_user_ids
    )


def cli_device_user_to_option() -> Any:
    return click.option(
        "--to", "device_user_ids",
        type=str,
        multiple=True,
        help=(
            "The id of the *device user* that a user / group should "
            "be authorized to."),
        envvar='NSF_CLI_SSH_DEVICE_USER_ID',
        # autocompletion=list_ac_available_device_user_ids
    )


def cli_device_user_to_all_flag() -> Any:
    return click.option(
        "--to-all", "device_user_all",
        is_flag=True,
        default=False,
        help=(
            "Whether to authorize the user / group to all "
            "*device users*"),
    )


def cli_device_user_from_option() -> Any:
    return click.option(
        "--from", "device_user_ids",
        type=str,
        multiple=True,
        help=(
            "The id of the device user that a user / group should "
            "be deauthorized from."),
        envvar='NSF_CLI_SSH_DEVICE_USER_ID',
        # autocompletion=list_ac_available_device_user_ids
    )


def cli_device_user_from_any_flag() -> Any:
    return click.option(
        "--from-any", "device_user_all",
        is_flag=True,
        default=False,
        help=(
            "Whether to deauthorize the user / group from any "
            "*device users*."),
    )


def cli_device_state_on_option() -> Any:
    return click.option(
        "--on", "device_state_ons",
        type=str,
        multiple=True,
        help=(
            "Constrain the user / group authorization / deauthorization"
            "to specific device states."),
        envvar='NSF_CLI_SSH_DEVICE_AUTH_STATE',
        # autocompletion=list_ac_available_device_state
    )


def cli_device_state_always_flag() -> Any:
    return click.option(
        "--always", "device_state_always",
        is_flag=True,
        default=False,
        help=(
            "When we want the user / group to be always authorized "
            "regardless of the current device state."),
    )
