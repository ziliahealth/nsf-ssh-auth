from abc import ABC, abstractmethod

from .types_pubkey import SshPubKeyLookupInfo
from .file_pubkey import get_default_lookup_info


class SshAuthDirPubkeyPolicy(ABC):
    @property
    @abstractmethod
    def default_lookup_info(self) -> SshPubKeyLookupInfo:
        pass


class SshAuthDirPubkeyDefaultPolicy(SshAuthDirPubkeyPolicy):
    def __init__(self) -> None:
        pass

    @property
    def default_lookup_info(self) -> SshPubKeyLookupInfo:
        return get_default_lookup_info()
