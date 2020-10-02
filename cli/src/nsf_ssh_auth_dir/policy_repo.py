from abc import ABC, abstractmethod

from .policy_file_format import (
    SshAuthDirFileFormatDefaultPolicy,
    SshAuthDirFileFormatPolicy,
)
from .policy_pubkey import SshAuthDirPubkeyDefaultPolicy, SshAuthDirPubkeyPolicy


class SshAuthDirRepoPolicy(ABC):
    @property
    @abstractmethod
    def file_format(self) -> SshAuthDirFileFormatPolicy:
        pass

    @property
    @abstractmethod
    def pubkey(self) -> SshAuthDirPubkeyPolicy:
        pass

    @property
    @abstractmethod
    def silent_create_file_users(self) -> bool:
        pass

    @property
    @abstractmethod
    def silent_create_file_groups(self) -> bool:
        pass

    @property
    @abstractmethod
    def silent_create_file_auth(self) -> bool:
        pass


class SshAuthDirRepoDefaultPolicy(SshAuthDirRepoPolicy):
    def __init__(self) -> None:
        pass

    @property
    def file_format(self) -> SshAuthDirFileFormatPolicy:
        return SshAuthDirFileFormatDefaultPolicy()

    @property
    def pubkey(self) -> SshAuthDirPubkeyPolicy:
        return SshAuthDirPubkeyDefaultPolicy()

    @property
    def silent_create_file_users(self) -> bool:
        return True

    @property
    def silent_create_file_groups(self) -> bool:
        return True

    @property
    def silent_create_file_auth(self) -> bool:
        return True
