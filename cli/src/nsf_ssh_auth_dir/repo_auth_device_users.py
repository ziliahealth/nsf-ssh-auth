from typing import Callable, Iterator, Optional, Set, Tuple, Type

from .file_auth import (
    SshAuthDumper,
    SshAuthFileAccessError,
    SshAuthFileError,
    SshAuthLoader,
    SshRawAuth,
    SshRawAuthDeviceUser
)
from .policy_repo import SshAuthDirRepoPolicy
from .repo_users import SshUser, SshUsersRepo
from .repo_groups import SshGroup, SshGroupsRepo
from .types_base_errors import SshAuthDirRepoError


class SshAuthRepoError(SshAuthDirRepoError):
    pass


class SshAuthRepoAccessError(SshAuthRepoError):
    pass


class SshAuthRepoFileAccessError(
        SshAuthRepoAccessError):
    pass


class SshAuthRepoKeyAccessError(
        SshAuthRepoAccessError, KeyError):
    pass


class SshAuthRepoGroupKeyAccessError(
        SshAuthRepoKeyAccessError):
    pass


class SshAuthRepoInvalidUserError(
        SshAuthRepoKeyAccessError):
    pass


class SshAuthRepoInvalidGroupError(
        SshAuthRepoKeyAccessError):
    pass


class SshAuthRepoDuplicateError(SshAuthRepoError):
    pass


class SshAuthRepoDeviceUserAlreadyExistsError(
        SshAuthRepoDuplicateError):
    pass


class SshAuthRepoUserAlreadyAuthorizedError(
        SshAuthRepoDuplicateError):
    pass


class SshAuthRepoGroupAlreadyAuthorizedError(
        SshAuthRepoDuplicateError):
    pass


def get_auth_repo_err_cls_from_auth_file_err(
        e: SshAuthFileError) -> Type[SshAuthRepoAccessError]:
    if isinstance(e, SshAuthFileAccessError):
        return SshAuthRepoFileAccessError

    return SshAuthRepoAccessError


class SshAuthDeviceUser:
    @staticmethod
    def get_sentinel_id_for_all() -> str:
        return ""

    def __init__(
            self,
            raw: SshRawAuthDeviceUser,
            update_raw_fn: Callable[[SshRawAuthDeviceUser], SshRawAuthDeviceUser],
            users: SshUsersRepo,
            groups: SshGroupsRepo,
            state_name: Optional[str]
    ) -> None:
        self._raw = raw
        self._update_raw_fn = update_raw_fn
        self._users = users
        self._groups = groups
        self._state_name = state_name

    @property
    def name(self) -> str:
        return self._raw.name

    @property
    def formatted_name(self) -> str:
        out = self.name
        if self.get_sentinel_id_for_all() == out:
            return "[ALL]"

        return out

    @property
    def state_name(self) -> Optional[str]:
        return self._state_name

    @property
    def formatted_state_name(self) -> str:
        name = self.state_name
        if name is None:
            return "[AUTH-ALWAYS]"

        return name

    @property
    def authorized_users_names(self) -> Set[str]:
        return self._raw.ssh_users

    def iter_authorized_users(
            self,
            skip_invalid: bool = False
    ) -> Iterator[SshUser]:
        # TODO: Flag to iterate users from groups too.
        for m_name in self.authorized_users_names:
            try:
                yield self._users[m_name]
            except KeyError:
                if not skip_invalid:
                    raise SshAuthRepoInvalidUserError(
                        f"'{self.formatted_name}' *device user* authorized "
                        f"user '{m_name}' does not correspond to a valid user."
                    )

    @property
    def authorized_users(self) -> Iterator[SshUser]:
        yield from self.iter_authorized_users()

    def authorize_user_by_id(self, user_id: str) -> None:
        if user_id not in self._users:
            raise SshAuthRepoInvalidUserError(
                f"Failed to authorize user '{user_id}' to *device user* "
                f"'{self.formatted_name}'. User does not exists."
            )

        if user_id in self.authorized_users_names:
            raise SshAuthRepoUserAlreadyAuthorizedError(
                f"Failed to authorize user '{user_id}' to *device user* "
                f"'{self.formatted_name}'. Already authorized."
            )

        self._raw.ssh_users.add(user_id)
        self._raw = self._update_raw_fn(self._raw)

    def deauthorize_user_by_id(self, authorized_user_id: str) -> None:
        # IDEA: Consider adding a flag to warn when user part of one of
        # the authorized group.
        try:
            self._raw.ssh_users.remove(authorized_user_id)
        except KeyError as e:
            raise SshAuthRepoKeyAccessError(
                f"No such user: '{authorized_user_id}' "
                "authorized to *device user* '{self.formatted_name}'."
                "Can't be deauthorized."
            ) from e
        self._raw = self._update_raw_fn(self._raw)

    @property
    def authorized_groups_names(self) -> Set[str]:
        return self._raw.ssh_groups

    def iter_authorized_groups(
            self,
            skip_invalid: bool = False
    ) -> Iterator[SshGroup]:
        for m_name in self.authorized_groups_names:
            try:
                yield self._groups[m_name]
            except KeyError:
                if not skip_invalid:
                    raise SshAuthRepoInvalidGroupError(
                        f"'{self.formatted_name}' *device user* authorized "
                        f"user '{m_name}' does not correspond to a valid user."
                    )

    @property
    def authorized_groups(self) -> Iterator[SshGroup]:
        yield from self.iter_authorized_groups()

    def authorize_group_by_id(self, group_id: str) -> None:
        if group_id not in self._groups:
            raise SshAuthRepoInvalidGroupError(
                f"Failed to authorize group '{group_id}' to *device user* "
                f"'{self.formatted_name}'. Group does not exists."
            )

        if group_id in self.authorized_groups_names:
            raise SshAuthRepoGroupAlreadyAuthorizedError(
                f"Failed to authorize group '{group_id}' to *device user* "
                f"'{self.formatted_name}'. Already authorized."
            )

        self._raw.ssh_groups.add(group_id)
        self._raw = self._update_raw_fn(self._raw)

    def deauthorize_group_by_id(self, authorized_group_id: str) -> None:
        try:
            self._raw.ssh_groups.remove(authorized_group_id)
        except KeyError as e:
            raise SshAuthRepoKeyAccessError(
                f"No such group: '{authorized_group_id}' "
                f"authorized to *device user* '{self.formatted_name}'."
                "Can't be deauthorized."
            ) from e
        self._raw = self._update_raw_fn(self._raw)


class SshAuthDeviceUsersRepo:
    def __init__(
            self,
            auth_loader: SshAuthLoader,
            auth_dumper: SshAuthDumper,
            policy: SshAuthDirRepoPolicy,
            users: SshUsersRepo,
            groups: SshGroupsRepo,
            state_name: Optional[str]
    ) -> None:
        self._policy = policy
        self._auth_loader = auth_loader
        self._auth_dumper = auth_dumper
        self._users = users
        self._groups = groups
        self._state_name = state_name

    @property
    def state_name(self) -> Optional[str]:
        return self._state_name

    def _update_raw_device_user(
            self, raw_du: SshRawAuthDeviceUser) -> SshRawAuthDeviceUser:
        raw = self._load_raw()

        if raw_du.name not in raw.device_users:
            raise SshAuthRepoKeyAccessError(
                f"No such *device user*: '{raw_du.name}'. Can't be updated.")

        raw.device_users[raw_du.name] = raw_du
        self._dump_raw(raw)

        raw = self._load_raw()
        return raw.device_users[raw_du.name]

    def _mk_du(
            self, raw: SshRawAuthDeviceUser
    ) -> SshAuthDeviceUser:
        return SshAuthDeviceUser(
            raw,
            self._update_raw_device_user,
            self._users,
            self._groups,
            self._state_name
        )

    def _load_raw(self) -> SshRawAuth:
        try:
            return self._auth_loader.load()
        except SshAuthFileError as e:
            ECls = get_auth_repo_err_cls_from_auth_file_err(e)
            raise ECls(str(e)) from e

    def _dump_raw(self, raw: SshRawAuth) -> None:
        try:
            return self._auth_dumper.dump(raw)
        except SshAuthFileError as e:
            ECls = get_auth_repo_err_cls_from_auth_file_err(e)
            raise ECls(str(e)) from e

    @property
    def names(self) -> Set[str]:
        raw_auth = self._load_raw()
        return {
            name for name in raw_auth.device_users.keys()
        }

    def __iter__(self) -> Iterator[SshAuthDeviceUser]:
        raw_auth = self._load_raw()
        for name, raw_du in raw_auth.device_users.items():
            yield self._mk_du(raw_du)

    def __contains__(self, du_name: str) -> bool:
        raw_auth = self._auth_loader.load()
        return du_name in raw_auth.device_users

    def _get_w_raw_set(self, du_name: str) -> Tuple[SshAuthDeviceUser, SshRawAuth]:
        raw_auth = self._load_raw()
        try:
            return (
                self._mk_du(
                    raw_auth.device_users[du_name]
                ),
                raw_auth
            )
        except KeyError as e:
            raise SshAuthRepoKeyAccessError(
                f"No such *device user*: '{du_name}'. Can't be returned.") from e

    def __getitem__(self, du_name: str) -> SshAuthDeviceUser:
        du, _ = self._get_w_raw_set(du_name)
        return du

    def __delitem__(self, du_name: str) -> None:
        raw_auth = self._load_raw()
        try:
            del raw_auth.device_users[du_name]
        except KeyError as e:
            raise SshAuthRepoKeyAccessError(
                f"No such *device user*: '{du_name}'. Can't be deleted.") from e
        self._dump_raw(raw_auth)

    def get(self, du_name: str,
            default: Optional[SshAuthDeviceUser] = None) -> Optional[SshAuthDeviceUser]:
        try:
            return self[du_name]
        except SshAuthRepoKeyAccessError:
            return default

    def get_all(
            self, default: Optional[SshAuthDeviceUser] = None
    ) -> Optional[SshAuthDeviceUser]:
        return self.get(
            SshAuthDeviceUser.get_sentinel_id_for_all(), default)

    def add(
            self,
            du_name: str,
            exist_ok: bool = False
    ) -> SshAuthDeviceUser:
        try:
            raw_auth = self._load_raw()
        except SshAuthRepoFileAccessError:
            if not self._policy.silent_create_file_auth:
                raise  # re-raise

            raw_auth = SshRawAuth.mk_empty()

        if du_name in raw_auth.device_users:
            if not exist_ok:
                raise SshAuthRepoDeviceUserAlreadyExistsError(
                    f"Failed to add *device user* '{du_name}'. Already exists.")
        else:
            raw_auth.device_users[du_name] = SshRawAuthDeviceUser.mk_new(
                du_name)
            self._dump_raw(raw_auth)

        du = self[du_name]
        return du

    def ensure(self, du_name: str) -> SshAuthDeviceUser:
        return self.add(du_name, exist_ok=True)

    def ensure_all(self) -> SshAuthDeviceUser:
        return self.add(
            SshAuthDeviceUser.get_sentinel_id_for_all(),
            exist_ok=True)

    def rm(
            self, du_name: str
    ) -> SshAuthDeviceUser:
        du, raw_auth = self._get_w_raw_set(du_name)

        # Should exist as we successfully retrieved the *device user*.
        del raw_auth.device_users[du_name]
        self._dump_raw(raw_auth)
        return du
