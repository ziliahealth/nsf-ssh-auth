import logging
from pathlib import Path
from nsf_ssh_auth_dir.repo import mk_ssh_auth_dir_repo

LOGGER = logging.getLogger(__name__)


def test_auth_device_users_case_1(tmp_case1_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case1_dir)
    LOGGER.info(f"repo: {repo.dir}")

    dus = repo.auth.always.device_users

    assert dus.names == {
        "my-device-user-b", "my-device-user-a", "my-device-user-c"
    }

    du_b = dus["my-device-user-b"]

    assert du_b.authorized_users_names == {
        "my-user-b"
    }
    assert du_b.authorized_groups_names == set()


def test_auth_device_users_case_2(tmp_case2_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case2_dir)
    LOGGER.info(f"repo: {repo.dir}")

    dus = repo.auth.always.device_users

    assert dus.names == {
        "",
        "my-device-user-a",
        "my-device-user-c",
        "my-device-user-d",
        "my-device-user-b"
    }

    du_b = dus["my-device-user-b"]

    assert du_b.authorized_users_names == {
        "my-ssh-user-d"
    }
    assert du_b.authorized_groups_names == set()
