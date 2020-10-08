from typing import Iterable, Iterator, List, Set, NamedTuple

from nsf_ssh_auth_dir.click.error import CliUsageError
from nsf_ssh_auth_dir.repo import SshAuthDirRepo
from nsf_ssh_auth_dir.repo_auth import SshAuthRepo
from nsf_ssh_auth_dir.repo_auth_device_users import (
    SshAuthDeviceUser,
    SshAuthRepoKeyAccessError,
)


def select_auth_device_users_where(
        repo: SshAuthDirRepo,
        device_user_ids: List[str],
        device_user_all: bool,
        device_state_ons: List[str],
        device_state_always: bool
) -> List[SshAuthDeviceUser]:
    if device_user_all and device_user_ids:
        raise CliUsageError(
            "When '--to-all' flag is specifed one should not "
            "provide any '--to' options. It simply makes no sense.")

    if device_state_always and device_state_ons:
        raise CliUsageError(
            "When '--always' flag is specifed one should not "
            "provide any '--on' options. It simply makes no sense.")

    auths: Iterable[SshAuthRepo]

    if device_state_always:
        auths = [repo.auth.always]
    else:
        auths = [
            repo.auth.on(d_state)
            for d_state in device_state_ons
        ]

    dus: List[SshAuthDeviceUser] = []

    for auth in auths:
        du_repo = auth.device_users
        if device_user_all:
            dus.append(du_repo.ensure_all())
        else:
            dus.extend(
                du_repo.ensure(du_id) for du_id in device_user_ids
            )

    if not dus:
        raise CliUsageError(
            "Nothing to do. "
            "Please provide missing *device user* or *device state* "
            "indications."
        )

    return dus


def iter_all_auth_device_users(
        repo: SshAuthDirRepo) -> Iterator[SshAuthDeviceUser]:
    for auth in repo.auth.all:
        yield from auth.device_users


class DeviceUserInfoUI(NamedTuple):
    fmt_name: str
    fmt_state_name: str

    @classmethod
    def mk_from(cls, device_user: SshAuthDeviceUser) -> 'DeviceUserInfoUI':
        return cls(
            device_user.formatted_name,
            device_user.formatted_state_name
        )


def deauthorize_user_from_all_auth_device_users(
        repo: SshAuthDirRepo,
        user_id: str,
        force: bool = False
) -> Set[DeviceUserInfoUI]:
    out = set()
    for du in iter_all_auth_device_users(repo):
        try:
            # TODO: We might want to warn instead. Consider.
            du.deauthorize_user_by_id(user_id, force=force)
            out.add(DeviceUserInfoUI.mk_from(du))
        except SshAuthRepoKeyAccessError:
            pass

    return out


def deauthorize_group_from_all_auth_device_users(
        repo: SshAuthDirRepo,
        group_id: str,
        force: bool = False
) -> Set[DeviceUserInfoUI]:
    out = set()
    for du in iter_all_auth_device_users(repo):
        try:
            du.deauthorize_group_by_id(group_id, force=force)
            out.add(DeviceUserInfoUI.mk_from(du))
        except SshAuthRepoKeyAccessError:
            pass

    return out
