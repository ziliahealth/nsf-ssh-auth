from typing import Iterable, Set, NamedTuple
from nsf_ssh_auth_dir.repo import SshAuthDirRepo
from nsf_ssh_auth_dir.repo_groups import SshGroupsRepoKeyAccessError, SshGroup


class GroupInfoUI(NamedTuple):
    fmt_name: str

    @classmethod
    def mk_from(cls, group: SshGroup) -> 'GroupInfoUI':
        return cls(group.name)


def add_user_to_groups(
        repo: SshAuthDirRepo,
        user_id: str,
        group_ids: Iterable[str]) -> None:
    for gid in group_ids:
        repo.groups.ensure(gid).add_member_by_id(user_id)


def rm_user_from_all_groups(
        repo: SshAuthDirRepo, user_id: str) -> Set[GroupInfoUI]:
    out = set()

    for g in repo.groups:
        try:
            g.rm_member_by_id(user_id)
            out.add(GroupInfoUI.mk_from(g))
        except SshGroupsRepoKeyAccessError:
            pass

    return out
