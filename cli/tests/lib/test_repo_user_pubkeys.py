

import logging
from typing import Iterable
from pathlib import Path
from nsf_ssh_auth_dir.repo import mk_ssh_auth_dir_repo

LOGGER = logging.getLogger(__name__)


def _check_pubkeys_filenames(
        sa_root_dir: Path,
        fns: Iterable[Path], expected_rfns: Iterable[str]
) -> None:
    actual_fns = list(fns)
    expected_rfns = set(expected_rfns)
    assert actual_fns
    assert all(map(lambda x: x.is_absolute(), actual_fns))
    assert all(map(lambda x: x.exists(), actual_fns))
    actual_rfns = set(str(pk.relative_to(sa_root_dir)) for pk in actual_fns)
    assert actual_rfns == expected_rfns


def test_ls_user_pubkeys_case_1(tmp_case1_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case1_dir)
    LOGGER.info(f"repo: {repo.dir}")

    ua_pk_fns = list(repo.users["my-user-a"].pubkeys.filenames)
    _check_pubkeys_filenames(repo.dir, ua_pk_fns, {
        "public-keys/my-user-a.rsa.pub",
        "public-keys/my-user-a.pub"
    })

    ub_pk_fns = list(repo.users["my-user-b"].pubkeys.filenames)
    _check_pubkeys_filenames(repo.dir, ub_pk_fns, {
        "public-keys/my-user-b.pub"
    })

    uf_pk_fns = list(repo.users["my-user-f"].pubkeys.filenames)
    _check_pubkeys_filenames(repo.dir, uf_pk_fns, {
        "public-keys-inherited/my-user-f.pub"
    })

    ug_pk_fns = list(repo.users["my-user-g"].pubkeys.filenames)
    _check_pubkeys_filenames(repo.dir, ug_pk_fns, {
        "public-keys-override/my-user-g.pub",
        "public-keys/my-user-g.rsa.pub"
    })


def test_ls_user_pubkeys_case_2(tmp_case2_dir: Path) -> None:
    repo = mk_ssh_auth_dir_repo(tmp_case2_dir)
    LOGGER.info(f"repo: {repo.dir}")

    ub_pk_fns = list(repo.users["my-user-b"].pubkeys.filenames)
    _check_pubkeys_filenames(repo.dir, ub_pk_fns, {
        "public-keys/my-user-b.pub"
    })
