from typing import Iterable, List, NamedTuple, Set, Tuple

from nsf_ssh_auth_dir.click.error import echo_error, CliError
from nsf_ssh_auth_dir.repo import SshAuthDirRepo
from nsf_ssh_auth_dir.repo_groups import (
    SshGroup,
    SshGroupsRepoAccessError,
    SshGroupsRepoKeyAccessError,
    SshGroupsRepoDuplicateError,
    SshGroupsRepoFileAccessError
)


class GroupInfoUI(NamedTuple):
    fmt_name: str

    @classmethod
    def mk_from(cls, group: SshGroup) -> 'GroupInfoUI':
        return cls(group.name)


def add_user_to_groups(
        repo: SshAuthDirRepo,
        user_id: str,
        group_ids: Iterable[str],
        force: bool) -> None:
    errors: List[Tuple[str, Exception]] = []

    for gid in group_ids:
        if force:
            repo.groups.ensure(gid).add_member_by_id(
                user_id, force=force)
        else:
            try:
                repo.groups[gid].add_member_by_id(user_id)
            except (SshGroupsRepoAccessError, SshGroupsRepoDuplicateError) as e:
                errors.append((gid, e))

    for gid, error in errors:
        echo_error(f"Error adding user to '{gid}':\n  {str(error)}")

    if errors:
        raise CliError(
            f"Was unable to add '{user_id}' to some of the"
            "specified groups. See previous log for more details.")


def rm_user_from_all_groups(
        repo: SshAuthDirRepo, user_id: str,
        force: bool = False
) -> Set[GroupInfoUI]:
    out = set()

    try:
        for g in repo.groups:
            try:
                # TODO: Consider some warning when not force.
                g.rm_member_by_id(user_id, force=force)
                out.add(GroupInfoUI.mk_from(g))
            except SshGroupsRepoKeyAccessError:
                pass
    except SshGroupsRepoFileAccessError:
        pass

    return out
