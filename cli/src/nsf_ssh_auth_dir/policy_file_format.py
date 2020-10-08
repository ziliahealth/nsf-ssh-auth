from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterable, Iterator


def _to_filename(dir: Path, stem: str, ext: str) -> Path:
    return dir.joinpath(stem).with_suffix(f".{ext}")


class SshAuthDirFileFormatPolicy(ABC):
    @abstractmethod
    def get_preferred_source_filename_for(
            self, dir: Path, stem: str) -> Path:
        pass

    @abstractmethod
    def get_source_filenames_for(
            self, dir: Path, stem: str) -> Iterable[Path]:
        pass

    @abstractmethod
    def get_target_filename_for(
            self, dir: Path, stem: str) -> Path:
        pass

    @abstractmethod
    def iter_target_filenames_in(
            self, dir: Path) -> Iterator[Path]:
        pass


class SshAuthDirFileFormatDefaultPolicy(
        SshAuthDirFileFormatPolicy):
    def __init__(self) -> None:
        pass

    def get_preferred_source_filename_for(
            self, dir: Path, stem: str) -> Path:
        return _to_filename(dir, stem, "json")

    def get_source_filenames_for(
            self, dir: Path, stem: str) -> Iterable[Path]:
        return [
            self.get_preferred_source_filename_for(dir, stem)
        ]

    def get_target_filename_for(
            self, dir: Path, stem: str) -> Path:
        return _to_filename(dir, stem, "json")

    def iter_target_filenames_in(
            self, dir: Path) -> Iterator[Path]:
        if not dir.exists():
            return

        for fp in dir.iterdir():
            if fp.is_dir():
                continue

            if ".json" == fp.suffix:
                yield fp
