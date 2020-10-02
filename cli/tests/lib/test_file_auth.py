import logging
from pathlib import Path
from nsf_ssh_auth_dir.file_auth import SshAuthLoader

LOGGER = logging.getLogger(__name__)


def test_auth_loader_case_2(tmp_case2_dir: Path) -> None:
    root_dir = tmp_case2_dir
    LOGGER.info(f"root_dir: {root_dir}")

    loader = SshAuthLoader(root_dir, "authorized-always")
    raw = loader.load()

    du_names = set(raw.device_users.keys())

    assert du_names == {
        "",
        "my-device-user-a",
        "my-device-user-c",
        "my-device-user-d",
        "my-device-user-b"
    }

    du_all = raw.device_users[""]
    assert du_all.ssh_users == {
        "my-ssh-user-e"
    }
    assert du_all.ssh_groups == set()

    du_c = raw.device_users["my-device-user-c"]
    assert du_c.ssh_users == {
        "my-ssh-user-d"
    }
    assert du_c.ssh_groups == {
        "my-group-2"
    }
