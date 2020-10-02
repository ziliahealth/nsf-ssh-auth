from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator, Optional, Set

from .file_auth import SshAuthDumper, SshAuthLoader
from .policy_repo import SshAuthDirRepoPolicy
from .repo_auth_device_users import SshAuthDeviceUsersRepo
from .repo_groups import SshGroupsRepo
from .repo_users import SshUsersRepo


class SshAuthRepo(ABC):
    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def state_name(self) -> Optional[str]:
        pass

    @property
    @abstractmethod
    def device_users(self) -> SshAuthDeviceUsersRepo:
        pass


class SshAuthCommonBase(SshAuthRepo):
    @abstractmethod
    def _is_always(self) -> bool:
        pass

    @property
    def name(self) -> str:
        if self._is_always():
            return self._stem

        return f"{self._dir.stem}-{self._stem}"

    @property
    def state_name(self) -> Optional[str]:
        if self._is_always():
            return None

        return self._stem

    def __init__(
            self,
            dir: Path,
            stem: str,
            policy: SshAuthDirRepoPolicy,
            users: SshUsersRepo,
            groups: SshGroupsRepo
    ) -> None:
        self._dir = dir
        self._stem = stem
        self._policy = policy
        self._users = users
        self._groups = groups
        self._loader = SshAuthLoader(dir, stem, policy.file_format)
        self._dumper = SshAuthDumper(dir, stem, policy.file_format)

    @property
    def device_users(self) -> SshAuthDeviceUsersRepo:
        return SshAuthDeviceUsersRepo(
            self._loader, self._dumper,
            self._policy,
            self._users, self._groups,
            self.state_name
        )


class SshAuthAlwaysRepo(SshAuthCommonBase):
    def _is_always(self) -> bool:
        return True


class SshAuthOnRepo(SshAuthCommonBase):
    def _is_always(self) -> bool:
        return False


class SshAuthSetRepo:
    def __init__(
            self,
            dir: Path,
            device_state_always_stem: str,
            device_state_on_dirname: str,
            policy: SshAuthDirRepoPolicy,
            users: SshUsersRepo,
            groups: SshGroupsRepo
    ) -> None:
        self._dir = dir
        self._state_always_stem = device_state_always_stem
        self._state_on_dir = dir.joinpath(device_state_on_dirname)
        self._policy = policy
        self._users = users
        self._groups = groups

    @property
    def always(self) -> SshAuthAlwaysRepo:
        return SshAuthAlwaysRepo(
            self._dir, self._state_always_stem,
            self._policy,
            self._users, self._groups
        )

    def on(self, state_id: str) -> SshAuthOnRepo:
        return SshAuthOnRepo(
            self._state_on_dir,
            state_id, self._policy,
            self._users, self._groups
        )

    def _iter_existing_on_files(self) -> Iterator[Path]:
        state_on_dir = self._state_on_dir
        yield from self._policy.file_format.iter_target_filenames_in(
            state_on_dir)

    def _get_existing_always_file(self) -> Optional[Path]:
        filename = self._policy.file_format.get_target_filename_for(
            self._dir, self._state_always_stem)
        if not filename.exists():
            return None

        return filename

    @property
    def state_names(self) -> Set[str]:
        return {
            fp.stem for fp in self._iter_existing_on_files()
        }

    @property
    def all(self) -> Iterator[SshAuthRepo]:
        if self._get_existing_always_file() is not None:
            yield self.always

        for ds_name in self.state_names:
            yield self.on(ds_name)
