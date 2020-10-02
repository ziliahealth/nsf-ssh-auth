import logging
from pathlib import Path
from typing import Set

from .types_base_errors import SshAuthDirFileError

from ._content_persistance_tools import (
    FileContentError,
    dump_content_to_file,
    load_content_from_file,
    get_opt_list_field_of_expected_type,
    mk_parent_dirs_opt,
    add_cond_to_dict_or_rm_key
)
from ._content_validation_tools import iter_duplicate_items

from .policy_file_format import SshAuthDirFileFormatPolicy
from .types_groups import SshPlainGroupsT, SshPlainGroupT, SshRawGroup, SshRawGroups

LOGGER = logging.getLogger(__name__)


class SshGroupsFileError(SshAuthDirFileError):
    pass


class SshGroupsFileAccessError(SshGroupsFileError):
    pass


class SshGroupsFileFormatError(SshGroupsFileError):
    pass


def load_plain_ssh_groups_from_file(
        filename: Path) -> SshPlainGroupsT:
    try:
        return load_content_from_file(filename)
    except FileContentError as e:
        raise SshGroupsFileAccessError(
            f"Cannot load device state file: {str(e)}")


def parse_ssh_group_members(
        name: str,
        plain: SshPlainGroupT
) -> Set[str]:
    members = get_opt_list_field_of_expected_type(
        plain, "members", str, SshGroupsFileFormatError)

    if members is None:
        members = []

    dups = list(iter_duplicate_items(members))
    if dups:
        dups_str = ", ".join(dups)
        LOGGER.warning(
            f"Group '{name}' contains duplicate members: {{{dups_str}}}")
    return set(members)


def parse_ssh_group(
        name: str,
        plain: SshPlainGroupT
) -> SshRawGroup:
    members = parse_ssh_group_members(name, plain)
    return SshRawGroup(plain, name, members)


def parse_ssh_groups(
        plain: SshPlainGroupsT
) -> SshRawGroups:

    plain_groups = plain.get("ssh-groups", {})

    groups_d = {
        g_name: parse_ssh_group(g_name, g_plain)
        for g_name, g_plain in plain_groups.items()
    }

    return SshRawGroups(plain, groups_d)


def load_ssh_groups_from_file(
        filename: Path) -> SshRawGroups:
    plain = load_plain_ssh_groups_from_file(filename)
    return parse_ssh_groups(plain)


def dump_plain_ssh_groups_to_file(
        groups: SshPlainGroupsT,
        out_filename: Path
) -> None:
    return dump_content_to_file(groups, out_filename)


def dump_ssh_group_to_plain_d(
        group: SshRawGroup
) -> SshPlainGroupT:
    out_d = {}
    out_d.update(group.plain)

    members = sorted(group.members)

    # Do not needlessly pollute file with empty sections.
    add_cond_to_dict_or_rm_key(
        bool(members),
        out_d, "members",
        members
    )

    return out_d


def dump_ssh_groups_to_plain_d(
    groups: SshRawGroups,
) -> SshPlainGroupsT:
    out_d = {}
    out_d.update(groups.plain)

    out_groups_d = {}
    for g_name, group in groups.ssh_groups.items():
        # We use the in-group name. This might mean
        # that the group was renamed.
        if g_name != group.name:
            LOGGER.info(f"Group: '{g_name}' renamed to '{group.name}'.")
        group_d = dump_ssh_group_to_plain_d(group)

        # A group can exist without any members.
        out_groups_d[group.name] = group_d

    # We will keep this attribute regardless if
    # it is empty as this gives a cue as to the
    # file format.
    out_d["ssh-groups"] = out_groups_d
    return out_d


def dump_ssh_groups_to_file(
        groups: SshRawGroups,
        out_filename: Path
) -> None:
    out_d = dump_ssh_groups_to_plain_d(groups)
    return dump_plain_ssh_groups_to_file(out_d, out_filename)


class SshGroupsLoader:
    def __init__(
            self,
            dir: Path, stem: str,
            policy: SshAuthDirFileFormatPolicy) -> None:
        self._filename = policy.get_preferred_source_filename_for(dir, stem)
        assert 1 == sum(1 for _ in policy.get_source_filenames_for(dir, stem))

    def load(self) -> SshRawGroups:
        return load_ssh_groups_from_file(self._filename)

    def load_plain(self) -> SshPlainGroupsT:
        return load_plain_ssh_groups_from_file(self._filename)


def _mk_parent_dirs_opt(filename: Path, allow: bool) -> None:
    mk_parent_dirs_opt(filename, allow)


class SshGroupsDumper:
    def __init__(
            self,
            dir: Path, stem: str,
            policy: SshAuthDirFileFormatPolicy) -> None:
        self._filename = policy.get_target_filename_for(dir, stem)

    def dump_plain(self, groups: SshPlainGroupsT) -> None:
        return dump_plain_ssh_groups_to_file(
            groups, self._filename)

    def dump(self, groups: SshRawGroups, mk_parent_dirs: bool = True) -> None:
        _mk_parent_dirs_opt(self._filename, mk_parent_dirs)
        return dump_ssh_groups_to_file(
            groups, self._filename)
