from dataclasses import dataclass


@dataclass
class SshAuthDirFileLayout:
    stem: str
    mandatory_file: bool


@dataclass
class SshAuthDirSubDirLayout:
    dirname: str


@dataclass
class SshAuthDirUsersFileLayout(SshAuthDirFileLayout):
    @classmethod
    def mk_default(cls) -> 'SshAuthDirUsersFileLayout':
        return cls(
            stem="users",
            # If the user file is missing, it is most likely an error.
            mandatory_file=False
        )


@dataclass
class SshAuthDirGroupsFileLayout(SshAuthDirFileLayout):
    @classmethod
    def mk_default(cls) -> 'SshAuthDirGroupsFileLayout':
        return cls(
            stem="groups",
            # If the user file is missing, it is most likely an error.
            mandatory_file=False
        )


@dataclass
class SshAuthDirAuthAlwaysFileLayout(SshAuthDirFileLayout):
    @classmethod
    def mk_default(cls) -> 'SshAuthDirAuthAlwaysFileLayout':
        return cls(
            stem="authorized-always",
            # This is alright to authorize on some state / moments only.
            mandatory_file=False
        )


@dataclass
class SshAuthDirAuthOnSubDirLayout(SshAuthDirSubDirLayout):
    @classmethod
    def mk_default(cls) -> 'SshAuthDirAuthOnSubDirLayout':
        return cls(
            dirname="authorized-on"
        )


@dataclass
class SshAuthDirLayout:
    users: SshAuthDirUsersFileLayout
    groups: SshAuthDirGroupsFileLayout
    device_state_always: SshAuthDirAuthAlwaysFileLayout
    auth_on: SshAuthDirAuthOnSubDirLayout

    @classmethod
    def mk_default(cls) -> 'SshAuthDirLayout':
        return cls(
            users=SshAuthDirUsersFileLayout.mk_default(),
            groups=SshAuthDirGroupsFileLayout.mk_default(),
            device_state_always=SshAuthDirAuthAlwaysFileLayout.mk_default(),
            auth_on=SshAuthDirAuthOnSubDirLayout.mk_default()
        )
