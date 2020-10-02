from pathlib import Path
from typing import Set, Type, Optional, Iterator, Tuple, Callable

from .file_groups import (SshGroupsDumper, SshGroupsFileAccessError,
                          SshGroupsFileError, SshGroupsLoader, SshRawGroup,
                          SshRawGroups)
from .policy_repo import SshAuthDirRepoPolicy
from .types_base_errors import SshAuthDirRepoError
from .repo_users import SshUsersRepo, SshUser


class SshGroupsRepoError(SshAuthDirRepoError):
    pass


class SshGroupsRepoAccessError(SshGroupsRepoError):
    pass


class SshGroupsRepoFileAccessError(SshGroupsRepoAccessError):
    pass


class SshGroupsRepoKeyAccessError(SshGroupsRepoAccessError, KeyError):
    pass


class SshGroupsRepoGroupKeyAccessError(SshGroupsRepoKeyAccessError):
    pass


class SshGroupsRepoInvalidUserError(SshGroupsRepoKeyAccessError):
    pass


class SshGroupsRepoDuplicateError(SshGroupsRepoError):
    pass


class SshGroupsRepoGroupAlreadyExistsError(
        SshGroupsRepoDuplicateError):
    pass


class SshGroupsRepoUserAlreadyGroupMemberError(
        SshGroupsRepoDuplicateError):
    pass


def get_groups_repo_err_cls_from_groups_file_err(
        e: SshGroupsFileError) -> Type[SshGroupsRepoAccessError]:
    if isinstance(e, SshGroupsFileAccessError):
        return SshGroupsRepoFileAccessError

    return SshGroupsRepoAccessError


class SshGroup:
    def __init__(
            self,
            sa_root_dir: Path,
            raw: SshRawGroup,
            update_raw_fn: Callable[[SshRawGroup], SshRawGroup],
            users: SshUsersRepo
    ) -> None:
        self._sa_root_dir = sa_root_dir
        self._raw = raw
        self._update_raw_fn = update_raw_fn
        self._users = users

    @property
    def name(self) -> str:
        return self._raw.name

    @property
    def members_names(self) -> Set[str]:
        return self._raw.members

    def iter_members(
            self,
            skip_invalid: bool = False
    ) -> Iterator[SshUser]:
        for m_name in self.members_names:
            try:
                yield self._users[m_name]
            except KeyError:
                if not skip_invalid:
                    raise SshGroupsRepoInvalidUserError(
                        f"'{self.name}' group member '{m_name}' does not "
                        "correspond to a valid user."
                    )

    @property
    def members(self) -> Iterator[SshUser]:
        yield from self.iter_members()

    def add_member_by_id(self, user_id: str) -> None:
        if user_id not in self._users:
            raise SshGroupsRepoInvalidUserError(
                f"Failed to add user '{user_id}' to group "
                f"'{self.name}'. User does not exists."
            )

        if user_id in self._raw.members:
            raise SshGroupsRepoUserAlreadyGroupMemberError(
                f"Failed to add user '{user_id}' to group "
                f"'{self.name}'. Already a member of this group."
            )

        self._raw.members.add(user_id)
        self._raw = self._update_raw_fn(self._raw)

    def rm_member_by_id(self, member_id: str) -> None:
        try:
            self._raw.members.remove(member_id)
        except KeyError as e:
            raise SshGroupsRepoKeyAccessError(
                f"No such '{self.name}' group member: '{member_id}'. "
                "Can't be removed."
            ) from e
        self._raw = self._update_raw_fn(self._raw)


class SshGroupsRepo:
    def __init__(
            self, dir: Path, stem: str,
            policy: SshAuthDirRepoPolicy,
            users: SshUsersRepo
    ) -> None:
        self._sa_root_dir = dir
        self._policy = policy
        self._groups_loader = SshGroupsLoader(dir, stem, policy.file_format)
        self._groups_dumper = SshGroupsDumper(dir, stem, policy.file_format)
        self._users = users

    def _update_raw_group(self, raw_group: SshRawGroup) -> SshRawGroup:
        raw = self._load_raw()

        if raw_group.name not in raw.ssh_groups:
            raise SshGroupsRepoKeyAccessError(
                f"No such group: '{raw_group.name}'. Can't be updated.")

        raw.ssh_groups[raw_group.name] = raw_group
        self._dump_raw(raw)

        raw = self._load_raw()
        return raw.ssh_groups[raw_group.name]

    def _mk_group(
            self, raw: SshRawGroup
    ) -> SshGroup:
        return SshGroup(
            self._sa_root_dir,
            raw,
            self._update_raw_group,
            self._users
        )

    def _load_raw(self) -> SshRawGroups:
        try:
            return self._groups_loader.load()
        except SshGroupsFileError as e:
            ECls = get_groups_repo_err_cls_from_groups_file_err(e)
            raise ECls(str(e)) from e

    def _dump_raw(self, raw: SshRawGroups) -> None:
        try:
            return self._groups_dumper.dump(raw)
        except SshGroupsFileError as e:
            ECls = get_groups_repo_err_cls_from_groups_file_err(e)
            raise ECls(str(e)) from e

    @property
    def names(self) -> Set[str]:
        raw_groups = self._load_raw()
        return {
            name for name in raw_groups.ssh_groups.keys()
        }

    def __iter__(self) -> Iterator[SshGroup]:
        raw_groups = self._load_raw()
        for name, group in raw_groups.ssh_groups.items():
            yield self._mk_group(group)

    def __contains__(self, groupname: str) -> bool:
        raw_groups = self._groups_loader.load()
        return groupname in raw_groups.ssh_groups

    def _get_w_raw_set(self, groupname: str) -> Tuple[SshGroup, SshRawGroups]:
        raw_groups = self._load_raw()
        try:
            return (
                self._mk_group(
                    raw_groups.ssh_groups[groupname]
                ),
                raw_groups
            )
        except KeyError as e:
            raise SshGroupsRepoKeyAccessError(
                f"No such group: '{groupname}'. Can't be returned.") from e

    def __getitem__(self, groupname: str) -> SshGroup:
        group, _ = self._get_w_raw_set(groupname)
        return group

    def __delitem__(self, groupname: str) -> None:
        raw_groups = self._load_raw()
        try:
            del raw_groups.ssh_groups[groupname]
        except KeyError as e:
            raise SshGroupsRepoKeyAccessError(
                f"No such group: '{groupname}'. Can't be deleted.") from e
        self._dump_raw(raw_groups)

    def get(self, groupname: str,
            default: Optional[SshGroup] = None) -> Optional[SshGroup]:
        try:
            return self[groupname]
        except SshGroupsRepoKeyAccessError:
            return default

    def add(
            self,
            groupname: str,
            exist_ok: bool = False
    ) -> SshGroup:
        try:
            raw_groups = self._load_raw()
        except SshGroupsRepoFileAccessError:
            if not self._policy.silent_create_file_groups:
                raise  # re-raise

            raw_groups = SshRawGroups.mk_empty()

        if groupname in raw_groups.ssh_groups:
            if not exist_ok:
                raise SshGroupsRepoGroupAlreadyExistsError(
                    f"Failed to add group '{groupname}'. Already exists.")
        else:
            raw_groups.ssh_groups[groupname] = SshRawGroup.mk_new(
                groupname)
            self._dump_raw(raw_groups)

        group = self.get(groupname, None)
        assert group is not None

        return group

    def ensure(self, groupname: str) -> SshGroup:
        return self.add(groupname, exist_ok=True)

    def rm(
            self, groupname: str
    ) -> SshGroup:
        group, raw_groups = self._get_w_raw_set(groupname)

        # Should exist as we successfully retrieved the group.
        del raw_groups.ssh_groups[groupname]
        self._dump_raw(raw_groups)
        return group
