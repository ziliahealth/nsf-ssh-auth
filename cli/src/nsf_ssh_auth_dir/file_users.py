import logging
from pathlib import Path

from .types_base_errors import SshAuthDirFileError

from ._content_persistance_tools import (
    FileContentError,
    dump_content_to_file,
    get_opt_field_of_expected_type,
    get_opt_list_field_of_expected_type,
    load_content_from_file,
    mk_parent_dirs_opt,
    add_cond_to_dict_or_rm_key
)
from .policy_file_format import SshAuthDirFileFormatPolicy
from .types_users import (
    SshPlainUserDefaultsT,
    SshPlainUserT,
    SshPlainUsersT,
    SshRawUser,
    SshRawUserDefaults,
    SshRawUsers
)

LOGGER = logging.getLogger(__name__)


class SshUsersFileError(SshAuthDirFileError):
    pass


class SshUsersFileAccessError(SshUsersFileError):
    pass


class SshUsersFileFormatError(SshUsersFileError):
    pass


def load_plain_ssh_users_from_file(
        filename: Path) -> SshPlainUsersT:
    try:
        return load_content_from_file(filename)
    except FileContentError as e:
        raise SshUsersFileAccessError(
            f"Cannot load device state file: {str(e)}")


def parse_ssh_user_defaults(
    plain: SshPlainUserDefaultsT
) -> SshRawUserDefaults:
    pubkey_file_template = get_opt_list_field_of_expected_type(
        plain, "pubkey-file-template",
        str, SshUsersFileFormatError)
    pubkey_file_search_path = get_opt_list_field_of_expected_type(
        plain, "pubkey-file-search-path",
        str, SshUsersFileFormatError)

    if pubkey_file_search_path is not None:
        pubkey_file_search_path = [Path(sp) for sp in pubkey_file_search_path]

    return SshRawUserDefaults(
        plain,
        pubkey_file_template,
        pubkey_file_search_path
    )


def parse_ssh_user(
    name: str,
    plain: SshPlainUserT
) -> SshRawUser:
    pubkey_file_template = get_opt_field_of_expected_type(
        plain, "pubkey-file-template",
        str, SshUsersFileFormatError)
    pubkey_file_search_path = get_opt_field_of_expected_type(
        plain, "pubkey-file-search-path",
        str, SshUsersFileFormatError)
    pubkey_file = get_opt_field_of_expected_type(
        plain, "pubkey-file",
        str, SshUsersFileFormatError)

    if pubkey_file_search_path is not None:
        pubkey_file_search_path = [Path(sp) for sp in pubkey_file_search_path]

    if pubkey_file is not None:
        pubkey_file = Path(pubkey_file)

    return SshRawUser(
        plain,
        name,
        pubkey_file_template,
        pubkey_file_search_path,
        pubkey_file
    )


def parse_ssh_users(
    plain: SshPlainUsersT
) -> SshRawUsers:
    plain_defaults = plain.get("ssh-user-defaults", None)

    defaults = None
    if plain_defaults is not None:
        defaults = parse_ssh_user_defaults(plain_defaults)

    plain_users = plain.get("ssh-users", {})

    users_d = {
        u_name: parse_ssh_user(u_name, u_plain)
        for u_name, u_plain in plain_users.items()
    }

    return SshRawUsers(plain, defaults, users_d)


def load_ssh_users_from_file(
        filename: Path) -> SshRawUsers:
    plain = load_plain_ssh_users_from_file(filename)
    return parse_ssh_users(plain)


def dump_plain_ssh_users_to_file(
        users: SshPlainUsersT,
        out_filename: Path
) -> None:
    return dump_content_to_file(users, out_filename)


def dump_ssh_user_defaults_to_plain_d(
    user_def: SshRawUserDefaults
) -> SshPlainUserDefaultsT:
    out_d = {}
    out_d.update(user_def.plain)

    add_cond_to_dict_or_rm_key(
        (user_def.pubkey_file_template is not None),
        out_d, "pubkey-file-template",
        lambda: user_def.pubkey_file_template
    )

    add_cond_to_dict_or_rm_key(
        (user_def.pubkey_file_search_path is not None),
        out_d, "pubkey-file-search-path",
        lambda: [
            str(sp) for sp in user_def.pubkey_file_search_path  # type: ignore
        ]
    )

    return out_d


def dump_ssh_user_to_plain_d(
        user: SshRawUser
) -> SshPlainUserT:
    out_d = {}
    out_d.update(user.plain)

    add_cond_to_dict_or_rm_key(
        (user.pubkey_file is not None),
        out_d, "pubkey-file",
        lambda: str(user.pubkey_file)
    )

    add_cond_to_dict_or_rm_key(
        (user.pubkey_file_template is not None),
        out_d, "pubkey-file-template",
        user.pubkey_file_template
    )

    add_cond_to_dict_or_rm_key(
        (user.pubkey_file_search_path is not None),
        out_d, "pubkey-file-search-path",
        lambda: str(user.pubkey_file_search_path)
    )

    return out_d


def dump_ssh_users_to_plain_d(
    users: SshRawUsers,
) -> SshPlainUsersT:
    out_d = {}
    out_d.update(users.plain)

    add_cond_to_dict_or_rm_key(
        (users.ssh_user_defaults is not None),
        out_d, "ssh-user-defaults",
        lambda: dump_ssh_user_defaults_to_plain_d(
            users.ssh_user_defaults)  # type: ignore
    )

    out_users_d = {}
    for u_name, user in users.ssh_users.items():
        # We use the in-user name. This might mean
        # that the user was renamed.
        if u_name != user.name:
            LOGGER.info(f"User: '{u_name}' renamed to '{user.name}'.")
        user_d = dump_ssh_user_to_plain_d(user)

        # A user is often found with empty attribute
        # set.
        out_users_d[user.name] = user_d

    # We will keep this attribute regardless if
    # it is empty as this gives a cue as to the
    # file format.
    out_d["ssh-users"] = out_users_d
    return out_d


def dump_ssh_users_to_file(
        users: SshRawUsers,
        out_filename: Path
) -> None:
    out_d = dump_ssh_users_to_plain_d(users)
    return dump_plain_ssh_users_to_file(out_d, out_filename)


class SshUsersLoader:
    def __init__(
            self,
            dir: Path, stem: str,
            policy: SshAuthDirFileFormatPolicy) -> None:
        self._filename = policy.get_preferred_source_filename_for(dir, stem)
        assert 1 == sum(1 for _ in policy.get_source_filenames_for(dir, stem))

    def load(self) -> SshRawUsers:
        return load_ssh_users_from_file(self._filename)

    def load_plain(self) -> SshPlainUsersT:
        return load_plain_ssh_users_from_file(self._filename)


def _mk_parent_dirs_opt(filename: Path, allow: bool) -> None:
    mk_parent_dirs_opt(filename, allow)


class SshUsersDumper:
    def __init__(
            self,
            dir: Path, stem: str,
            policy: SshAuthDirFileFormatPolicy) -> None:
        self._filename = policy.get_target_filename_for(dir, stem)

    def dump_plain(self, users: SshPlainUsersT, mk_parent_dirs=True) -> None:
        _mk_parent_dirs_opt(self._filename, mk_parent_dirs)
        return dump_plain_ssh_users_to_file(
            users, self._filename)

    def dump(self, users: SshRawUsers, mk_parent_dirs=True) -> None:
        _mk_parent_dirs_opt(self._filename, mk_parent_dirs)
        return dump_ssh_users_to_file(
            users, self._filename)
