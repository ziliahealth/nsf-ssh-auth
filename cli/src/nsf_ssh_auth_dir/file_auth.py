import logging
from pathlib import Path
from typing import Optional, Set

from ._content_persistance_tools import (
    FileContentError,
    add_cond_to_dict_or_rm_key,
    dump_content_to_file,
    get_opt_list_field_of_expected_type,
    load_content_from_file,
    mk_parent_dirs_opt,
)
from ._content_validation_tools import iter_duplicate_items
from .policy_file_format import (
    SshAuthDirFileFormatDefaultPolicy,
    SshAuthDirFileFormatPolicy,
)
from .types_auth import (
    SshPlainAuthDeviceUserT,
    SshPlainAuthT,
    SshRawAuth,
    SshRawAuthDeviceUser,
)
from .types_base_errors import SshAuthDirFileError

LOGGER = logging.getLogger(__name__)


class SshAuthFileError(SshAuthDirFileError):
    pass


class SshAuthFileAccessError(SshAuthFileError):
    pass


class SshAuthFileFormatError(SshAuthFileError):
    pass


def load_plain_ssh_auth_from_file(
        filename: Path) -> SshPlainAuthT:
    try:
        return load_content_from_file(filename)
    except FileContentError as e:
        raise SshAuthFileAccessError(
            f"Cannot load device state file: {str(e)}")


def parse_ssh_auth_device_user_groups(
        name: str,
        plain: SshPlainAuthDeviceUserT) -> Set[str]:
    groups = get_opt_list_field_of_expected_type(
        plain, "ssh-groups", str, SshAuthFileFormatError)

    if groups is None:
        groups = []

    dups = list(iter_duplicate_items(groups))
    if dups:
        dups_str = ", ".join(dups)
        LOGGER.warning(
            f"Device user '{name}' contains duplicate groups: {{{dups_str}}}")

    return set(groups)


def parse_ssh_auth_device_user_users(
        name: str,
        plain: SshPlainAuthDeviceUserT) -> Set[str]:
    users = get_opt_list_field_of_expected_type(
        plain, "ssh-users", str, SshAuthFileFormatError)

    if users is None:
        users = []

    dups = list(iter_duplicate_items(users))
    if dups:
        dups_str = ", ".join(dups)
        LOGGER.warning(
            f"Device user '{name}' contains duplicate users: {{{dups_str}}}")

    return set(users)


def parse_ssh_auth_device_user(
        name: str,
        plain: SshPlainAuthDeviceUserT) -> SshRawAuthDeviceUser:
    groups = parse_ssh_auth_device_user_groups(name, plain)
    users = parse_ssh_auth_device_user_users(name, plain)
    return SshRawAuthDeviceUser(plain, name, groups, users)


def parse_ssh_auth(plain: SshPlainAuthT) -> SshRawAuth:
    plain_device_users = plain.get("device-users", {})

    device_users_d = {
        du_name: parse_ssh_auth_device_user(du_name, du_plain)
        for du_name, du_plain in plain_device_users.items()
    }

    return SshRawAuth(plain, device_users_d)


def load_ssh_auth_from_file(
        filename: Path) -> SshRawAuth:
    plain = load_plain_ssh_auth_from_file(filename)
    return parse_ssh_auth(plain)


def dump_plain_ssh_auth_to_file(
        auth: SshPlainAuthT,
        out_filename: Path
) -> None:
    return dump_content_to_file(auth, out_filename)


def dump_ssh_auth_device_user_to_plain_d(
    device_user: SshRawAuthDeviceUser,
) -> SshPlainAuthDeviceUserT:
    out_d = {}
    out_d.update(device_user.plain)

    groups = sorted(device_user.ssh_groups)
    # Do not needlessly pollute file with empty sections.
    add_cond_to_dict_or_rm_key(
        bool(groups),
        out_d, "ssh-groups",
        groups
    )

    users = sorted(device_user.ssh_users)
    # Do not needlessly pollute file with empty sections.
    add_cond_to_dict_or_rm_key(
        bool(users),
        out_d, "ssh-users",
        users
    )

    return out_d


def dump_ssh_auth_to_plain_d(
    auth: SshRawAuth,
) -> SshPlainAuthT:
    out_d = {}
    out_d.update(auth.plain)

    out_du_d = {}
    for du_name, du in auth.device_users.items():
        # We use the in-device-user name. This might mean
        # that the device user was renamed.
        if du_name != du.name:
            LOGGER.info(f"Device user: '{du_name}' renamed to '{du.name}'.")

        du_d = dump_ssh_auth_device_user_to_plain_d(du)
        # Even though it might seem pointless we will
        # keep empty device users. This might be be
        # usefull for autocompletion.
        out_du_d[du.name] = du_d

    # We will keep this attribute regardless if
    # it is empty as this gives a cue as to the
    # file format.
    out_d["device-users"] = out_du_d
    return out_d


def dump_ssh_auth_to_file(
        auth: SshRawAuth,
        out_filename: Path
) -> None:
    out_d = dump_ssh_auth_to_plain_d(auth)
    return dump_plain_ssh_auth_to_file(out_d, out_filename)


class SshAuthLoader:
    def __init__(
            self,
            dir: Path, stem: str,
            policy: Optional[SshAuthDirFileFormatPolicy] = None) -> None:
        if policy is None:
            policy = SshAuthDirFileFormatDefaultPolicy()

        self._filename = policy.get_preferred_source_filename_for(dir, stem)
        assert 1 == sum(1 for _ in policy.get_source_filenames_for(dir, stem))

    def load(self) -> SshRawAuth:
        return load_ssh_auth_from_file(self._filename)

    def load_plain(self) -> SshPlainAuthT:
        return load_plain_ssh_auth_from_file(self._filename)


def _mk_parent_dirs_opt(filename: Path, allow: bool) -> None:
    mk_parent_dirs_opt(filename, allow)


class SshAuthDumper:
    def __init__(
            self,
            dir: Path, stem: str,
            policy: SshAuthDirFileFormatPolicy) -> None:
        self._filename = policy.get_target_filename_for(dir, stem)

    def dump_plain(
            self,
            auth: SshPlainAuthT, mk_parent_dirs: bool = True) -> None:
        _mk_parent_dirs_opt(self._filename, mk_parent_dirs)
        return dump_plain_ssh_auth_to_file(
            auth, self._filename)

    def dump(self, auth: SshRawAuth, mk_parent_dirs: bool = True) -> None:
        _mk_parent_dirs_opt(self._filename, mk_parent_dirs)
        return dump_ssh_auth_to_file(
            auth, self._filename)
