import pytest
from shutil import copytree
from _pytest.tmpdir import TempPathFactory
from pathlib import Path

from test_lib.data import get_test_data_dir


def _get_case_x_repo_src_dir(idx: int) -> Path:
    return get_test_data_dir().joinpath(f"case{idx}/device-ssh")


def _mk_case_x_writable_tmp_fixture_dir(
        idx: int, tmp_path_factory: TempPathFactory) -> Path:
    tmp_dir = tmp_path_factory.mktemp(f"case{idx}_sad")
    tmp_cwd_dir = tmp_dir.joinpath("device-ssh")
    copytree(_get_case_x_repo_src_dir(idx), tmp_cwd_dir)
    return tmp_cwd_dir


@pytest.fixture
def tmp_case1_dir(tmp_path_factory: TempPathFactory) -> Path:
    return _mk_case_x_writable_tmp_fixture_dir(1, tmp_path_factory)


@pytest.fixture
def tmp_case2_dir(tmp_path_factory: TempPathFactory) -> Path:
    return _mk_case_x_writable_tmp_fixture_dir(2, tmp_path_factory)
