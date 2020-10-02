from dataclasses import dataclass
from typing import List, Optional, Iterable
from pathlib import Path


@dataclass
class SshPubKeyFileTemplateVars:
    username: str


@dataclass
class SshPubKeyLookupInfo:
    file_template: Iterable[str]
    file_search_path: Iterable[Path]
    file: Optional[Path]


@dataclass
class SshPubKeyLookupInfoOpt:
    file_template: Optional[Iterable[str]]
    file_search_path: Optional[Iterable[Path]]
    file: Optional[Path]


@dataclass
class SshPubKey:
    # IDEA: Type (rsa, etc).
    # Line of the ssh pubkey file including line jump.
    text_lines: List[str]
