from dataclasses import dataclass
from typing import Dict, Any, Set

SshPlainAuthDeviceUserT = Dict[str, Any]
SshPlainAuthT = Dict[str, Any]


@dataclass
class SshRawAuthDeviceUser:
    plain: SshPlainAuthDeviceUserT
    name: str
    ssh_groups: Set[str]
    ssh_users: Set[str]

    @classmethod
    def mk_new(cls, name) -> 'SshRawAuthDeviceUser':
        return cls({}, name, set(), set())


@dataclass
class SshRawAuth:
    plain: SshPlainAuthT
    device_users: Dict[str, SshRawAuthDeviceUser]

    @classmethod
    def mk_empty(cls) -> 'SshRawAuth':
        return cls({}, {})
