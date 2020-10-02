from dataclasses import dataclass
from typing import Dict, Any, Iterable, Optional
from pathlib import Path

SshPlainUserDefaultsT = Dict[str, Any]
SshPlainUserT = Dict[str, Any]
SshPlainUsersT = Dict[str, Any]


@dataclass
class SshRawUserDefaults:
    plain: SshPlainUserDefaultsT
    pubkey_file_template: Optional[Iterable[str]]
    pubkey_file_search_path: Optional[Iterable[Path]]


@dataclass
class SshRawUser:
    plain: SshPlainUserT
    name: str
    pubkey_file_template: Optional[str]
    pubkey_file_search_path: Optional[Path]
    pubkey_file: Optional[Path]

    @classmethod
    def mk_new(cls, name) -> 'SshRawUser':
        return cls({}, name, None, None, None)


@dataclass
class SshRawUsers:
    plain: SshPlainUsersT
    ssh_user_defaults: Optional[SshRawUserDefaults]
    ssh_users: Dict[str, SshRawUser]

    @classmethod
    def mk_empty(cls) -> 'SshRawUsers':
        return cls({}, None, {})
