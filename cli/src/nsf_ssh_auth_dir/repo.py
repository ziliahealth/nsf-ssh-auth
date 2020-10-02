"""Module defining the ssh auth dir concept.

Should match `nix-lib/dir.nix` nix side module.

TODO: It would be best were its default parameters shared via a common file.
"""
from pathlib import Path
from typing import Optional

from .policy_repo import SshAuthDirRepoDefaultPolicy, SshAuthDirRepoPolicy
from .repo_auth import SshAuthSetRepo
from .repo_groups import SshGroupsRepo
from .repo_users import SshUsersRepo
from .types_layout import SshAuthDirLayout


class SshAuthDirRepo:
    def __init__(
            self,
            dir: Path,
            layout: SshAuthDirLayout,
            policy: SshAuthDirRepoPolicy
    ) -> None:
        self._dir = dir
        self._layout = layout
        self._policy = policy

    @property
    def dir(self) -> Path:
        return self._dir

    @property
    def users(self) -> SshUsersRepo:
        return SshUsersRepo(
            self.dir,
            self._layout.users.stem,
            self._policy
        )

    @property
    def groups(self) -> SshGroupsRepo:
        return SshGroupsRepo(
            self.dir,
            self._layout.groups.stem,
            self._policy,
            self.users
        )

    @property
    def auth(self) -> SshAuthSetRepo:
        return SshAuthSetRepo(
            self.dir,
            self._layout.device_state_always.stem,
            self._layout.auth_on.dirname,
            self._policy,
            self.users,
            self.groups
        )


def mk_ssh_auth_dir_repo(
    dir: Path,
    layout: Optional[SshAuthDirLayout] = None,
    policy: Optional[SshAuthDirRepoPolicy] = None
) -> SshAuthDirRepo:

    if layout is None:
        layout = SshAuthDirLayout.mk_default()

    if policy is None:
        policy = SshAuthDirRepoDefaultPolicy()

    return SshAuthDirRepo(
        dir,
        layout,
        policy
    )
