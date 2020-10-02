from dataclasses import dataclass
from typing import Dict, Any, Set

SshPlainGroupT = Dict[str, Any]
SshPlainGroupsT = Dict[str, Any]


@dataclass
class SshRawGroup:
    plain: SshPlainGroupT
    name: str
    members: Set[str]

    @classmethod
    def mk_new(cls, name) -> 'SshRawGroup':
        return SshRawGroup({}, name, set())


@dataclass
class SshRawGroups:
    plain: SshPlainGroupsT
    ssh_groups: Dict[str, SshRawGroup]

    @classmethod
    def mk_empty(cls) -> 'SshRawGroups':
        return cls({}, {})
