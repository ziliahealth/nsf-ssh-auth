class SshAuthDirError(Exception):
    pass


class SshAuthDirFileError(SshAuthDirError):
    # A lower lever file access layer kind of exception.
    pass


class SshAuthDirRepoError(SshAuthDirError):
    # A higher level layer kind of exception.
    pass
