import pytest
import logging
from typing import Set
from pathlib import Path
from nsf_ssh_auth_dir.repo import mk_ssh_auth_dir_repo, SshAuthDirRepo
from nsf_ssh_auth_dir.repo_users import SshUsersRepoFileAccessError, SshPubKey

LOGGER = logging.getLogger(__name__)


def get_expected_usernames_case1() -> Set[str]:
    return {
        "my-user-a",
        "my-user-b",
        "my-user-c",
        "my-user-d",
        "my-user-e",
        "my-user-f",
        "my-user-g"
    }


def get_expected_usernames_case2() -> Set[str]:
    return {
        "my-user-a",
        "my-user-b",
        "my-user-c",
        "my-user-d",
        "my-user-e"
    }


def test_ls_usernames_case_1(tmp_case1_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case1_dir)

    LOGGER.info(f"repo: {repo.dir}")

    names = set(repo.users.names)

    assert names == get_expected_usernames_case1()


def test_ls_usernames_case_2(tmp_case2_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case2_dir)
    LOGGER.info(f"repo: {repo.dir}")

    names = set(repo.users.names)

    assert names == get_expected_usernames_case2()


def test_get_user_case_1(tmp_case1_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case1_dir)
    LOGGER.info(f"repo: {repo.dir}")

    user_a = repo.users["my-user-a"]
    assert user_a.name == "my-user-a"
    assert user_a.pubkey_default.text_lines == ["my-user-a.pub"]
    assert user_a.pubkey_selected.text_lines == ["my-user-a.rsa.pub"]

    user_b = repo.users["my-user-b"]
    assert user_b.name == "my-user-b"
    assert user_b.pubkey_default.text_lines == ["my-user-b.pub"]
    assert user_b.pubkey_selected.text_lines == ["my-user-b.pub"]

    user_c = repo.users["my-user-c"]
    assert user_c.name == "my-user-c"
    assert user_c.pubkey_default.text_lines == ["my-user-c.ed25519.pub"]
    assert user_c.pubkey_selected.text_lines == ["my-user-c.ed25519.pub"]

    user_d = repo.users["my-user-d"]
    assert user_d.name == "my-user-d"
    assert user_d.pubkey_default.text_lines == ["my-user-d.ed25519.pub"]
    assert user_d.pubkey_selected.text_lines == ["my-user-d.ed25519.pub"]

    user_e = repo.users["my-user-e"]
    assert user_e.name == "my-user-e"
    assert user_e.pubkey_default.text_lines == ["my-user-e.pub"]
    assert user_e.pubkey_selected.text_lines == ["my-user-e.pub"]

    user_f = repo.users["my-user-f"]
    assert user_f.name == "my-user-f"
    with pytest.raises(SshUsersRepoFileAccessError):
        user_f.pubkey_default
    assert user_f.pubkey_selected.text_lines == ["inherited/my-user-f.pub"]

    user_g = repo.users["my-user-g"]
    assert user_g.name == "my-user-g"
    with pytest.raises(SshUsersRepoFileAccessError):
        user_g.pubkey_default
    assert user_g.pubkey_selected.text_lines == ["override/my-user-g.pub"]


def test_get_user_case_2(tmp_case2_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case2_dir)
    LOGGER.info(f"repo: {repo.dir}")

    user_b = repo.users["my-user-b"]

    assert user_b.name == "my-user-b"
    assert user_b.pubkey_default.text_lines == ["my-user-b.pub"]
    assert user_b.pubkey_selected.text_lines == ["my-user-b.pub"]


def _check_add_user_set_pubkey(
        repo: SshAuthDirRepo, expected_usernames: Set[str]) -> None:
    names = set(repo.users.names)
    assert names == expected_usernames

    repo.users.add("my-new-user-1")
    assert set(repo.users.names) == (expected_usernames | {"my-new-user-1"})

    u1_new = repo.users["my-new-user-1"]
    with pytest.raises(SshUsersRepoFileAccessError):
        u1_new.pubkey_default

    u1_pk = SshPubKey(["my-new-user-1.pub"])
    u1_new.pubkey_default = u1_pk

    assert u1_pk == u1_new.pubkey_default

    u2_pk = SshPubKey(["my-new-user-2.pub"])
    u2_new = repo.users.add("my-new-user-2", u2_pk)
    assert set(repo.users.names) == (
        expected_usernames | {"my-new-user-1", "my-new-user-2"})

    assert "my-new-user-2" == u2_new.name
    assert u2_pk == u2_new.pubkey_default

    u2_new = repo.users["my-new-user-2"]
    assert u2_pk == u2_new.pubkey_default


def test_add_user_set_pubkey_case_1(tmp_case1_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case1_dir)

    LOGGER.info(f"repo: {repo.dir}")

    _check_add_user_set_pubkey(repo, get_expected_usernames_case1())


def test_add_user_set_pubkey_case_2(tmp_case2_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case2_dir)

    LOGGER.info(f"repo: {repo.dir}")

    _check_add_user_set_pubkey(repo, get_expected_usernames_case2())
