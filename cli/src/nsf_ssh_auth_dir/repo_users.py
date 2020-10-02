from pathlib import Path
from typing import Iterator, Optional, Type, Tuple, Set

from .file_users import (
    SshUsersDumper,
    SshUsersFileAccessError,
    SshUsersFileError,
    SshUsersLoader,
)
from .policy_repo import SshAuthDirPubkeyPolicy, SshAuthDirRepoPolicy
from .repo_user_pubkeys import (
    SshUserPubkeysRepo,
    SshUserPubkeysRepoError,
    SshUserPubkeysRepoFileAccessError,
)
from .types_base_errors import SshAuthDirRepoError
from .types_pubkey import SshPubKey
from .types_users import SshRawUser, SshRawUserDefaults, SshRawUsers


class SshUsersRepoError(SshAuthDirRepoError):
    pass


class SshUsersRepoAccessError(SshUsersRepoError):
    pass


class SshUsersRepoFileAccessError(SshUsersRepoAccessError):
    pass


class SshUsersRepoKeyAccessError(SshUsersRepoAccessError, KeyError):
    pass


class SshUsersRepoDuplicateError(SshUsersRepoError):
    pass


class SshUsersRepoUserAlreadyExistsError(SshUsersRepoDuplicateError):
    pass


def get_users_repo_err_cls_from_users_file_err(
        e: SshUsersFileError) -> Type[SshUsersRepoAccessError]:
    if isinstance(e, SshUsersFileAccessError):
        return SshUsersRepoFileAccessError

    return SshUsersRepoAccessError


def get_users_repo_err_cls_from_user_pubkeys_repo_err(
        e: SshUserPubkeysRepoError) -> Type[SshUsersRepoAccessError]:
    if isinstance(e, SshUserPubkeysRepoFileAccessError):
        return SshUsersRepoFileAccessError

    return SshUsersRepoAccessError


class SshUser:
    def __init__(
            self,
            sa_root_dir: Path,
            raw: SshRawUser,
            raw_defaults: Optional[SshRawUserDefaults],
            pubkey_policy: SshAuthDirPubkeyPolicy
    ) -> None:
        self._sa_root_dir = sa_root_dir
        self._raw = raw
        self._raw_defaults = raw_defaults
        self._pubkeys = SshUserPubkeysRepo(
            sa_root_dir, raw, raw_defaults, pubkey_policy)

    @property
    def name(self) -> str:
        return self._raw.name

    @property
    def pubkeys(self) -> SshUserPubkeysRepo:
        return self._pubkeys

    @property
    def pubkey_selected(self) -> SshPubKey:
        try:
            return self._pubkeys.selected
        except SshUserPubkeysRepoError as e:
            ECls = get_users_repo_err_cls_from_user_pubkeys_repo_err(e)
            raise ECls(str(e)) from e

    @property
    def pubkey_default(self) -> SshPubKey:
        try:
            return self._pubkeys.default
        except SshUserPubkeysRepoError as e:
            ECls = get_users_repo_err_cls_from_user_pubkeys_repo_err(e)
            raise ECls(str(e)) from e

    @pubkey_default.setter
    def pubkey_default(self, pubkey: SshPubKey) -> None:
        try:
            self._pubkeys.default = pubkey
        except SshUserPubkeysRepoError as e:
            ECls = get_users_repo_err_cls_from_user_pubkeys_repo_err(e)
            raise ECls(str(e)) from e


class SshUsersRepo:
    def __init__(
            self, dir: Path, stem: str,
            policy: SshAuthDirRepoPolicy
    ) -> None:
        self._sa_root_dir = dir
        self._policy = policy
        self._users_loader = SshUsersLoader(dir, stem, policy.file_format)
        self._users_dumper = SshUsersDumper(dir, stem, policy.file_format)

    def _mk_user(
            self, raw: SshRawUser,
            raw_defaults: Optional[SshRawUserDefaults]
    ) -> SshUser:
        return SshUser(
            self._sa_root_dir,
            raw,
            raw_defaults,
            self._policy.pubkey
        )

    def _load_raw(self) -> SshRawUsers:
        try:
            return self._users_loader.load()
        except SshUsersFileError as e:
            ECls = get_users_repo_err_cls_from_users_file_err(e)
            raise ECls(str(e)) from e

    def _dump_raw(self, raw: SshRawUsers) -> None:
        try:
            return self._users_dumper.dump(raw)
        except SshUsersFileError as e:
            ECls = get_users_repo_err_cls_from_users_file_err(e)
            raise ECls(str(e)) from e

    @property
    def names(self) -> Set[str]:
        raw_users = self._load_raw()
        return {
            name for name in raw_users.ssh_users.keys()
        }

    def __iter__(self) -> Iterator[SshUser]:
        raw_users = self._load_raw()
        for name, user in raw_users.ssh_users.items():
            yield self._mk_user(
                user,
                raw_users.ssh_user_defaults)

    def __contains__(self, username: str) -> bool:
        raw_users = self._users_loader.load()
        return username in raw_users.ssh_users

    def _get_w_raw_set(self, username: str) -> Tuple[SshUser, SshRawUsers]:
        raw_users = self._load_raw()
        try:
            return (
                self._mk_user(
                    raw_users.ssh_users[username],
                    raw_users.ssh_user_defaults
                ),
                raw_users
            )
        except KeyError as e:
            raise SshUsersRepoKeyAccessError(
                f"No such user: '{username}'. Can't be returned.") from e

    def __getitem__(self, username: str) -> SshUser:
        user, _ = self._get_w_raw_set(username)
        return user

    def __delitem__(self, username: str) -> None:
        raw_users = self._load_raw()
        try:
            del raw_users.ssh_users[username]
        except KeyError as e:
            raise SshUsersRepoKeyAccessError(
                f"No such user: '{username}'. Can't be deleted.") from e
        self._dump_raw(raw_users)

    def get(self, username: str,
            default: Optional[SshUser] = None) -> Optional[SshUser]:
        try:
            return self[username]
        except SshUsersRepoKeyAccessError:
            return default

    def add(
            self,
            username: str,
            pubkey: Optional[SshPubKey] = None,
            exist_ok: bool = False
    ) -> SshUser:
        try:
            raw_users = self._load_raw()
        except SshUsersRepoFileAccessError:
            if not self._policy.silent_create_file_users:
                raise  # re-raise

            raw_users = SshRawUsers.mk_empty()

        if username in raw_users.ssh_users:
            if not exist_ok:
                raise SshUsersRepoUserAlreadyExistsError(
                    f"Failed to add user '{username}'. Already exists.")
        else:
            raw_users.ssh_users[username] = SshRawUser.mk_new(
                username)
            self._dump_raw(raw_users)

        user = self[username]

        if pubkey is not None:
            user.pubkey_default = pubkey

        return user

    def rm(
            self, username: str, with_pubkeys=True
    ) -> SshUser:
        user, raw_users = self._get_w_raw_set(username)
        if with_pubkeys:
            user.pubkeys.rm_all()

        # Should exist as we successfully retrieved the user.
        del raw_users.ssh_users[username]
        self._dump_raw(raw_users)
        return user
