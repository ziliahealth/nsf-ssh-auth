from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Union, List

import click

from nsf_ssh_auth_dir.click.ctx_dict import (
    init_ctx_dict_instance,
    mk_ctx_dict_pass_decorator,
)
from nsf_ssh_auth_dir.repo import SshAuthDirRepo, mk_ssh_auth_dir_repo

from .._ctx import CliCtxDbBase, get_cli_ctx_db_base, mk_cli_db_obj_d
from .._ctx_default_user import CliCtxDbWDefaultUser


class CliCtxDbInterface(
        CliCtxDbWDefaultUser
):
    """The cli context occuring before anything is known / set.

    Mainly used by autocompletion callbacks and potentially
    options callbacks if any.

    This was required in order to parameterize the autocompletion logic.

    This should be provided as initial `obj` through the top level group's
    `context_settings`.

    See below `mk_cli_context_settings`.
    """
    """
    @abstractmethod
    def get_ac_cwd(
            self, ctx: click.Context, args: List[str]
    ) -> Optional[Path]:
        pass

    @abstractmethod
    def get_ac_user_id(
            self, ctx: click.Context, args: List[str]
    ) -> Optional[str]:
        pass
    """
    def get_default_user_id(
            self, ctx: click.Context, args: List[str]) -> Optional[str]:
        # TODO: Infer from file / context / args.
        return None


def mk_cli_context_settings(
    mk_db: CliCtxDbBase.MkFnT,
    db_key: Optional[str] = None
) -> Dict[str, Any]:
    """Create initial click context parameters for this cli application.

    This is currently used as input for autocompletion.

    Example:
        `@click.group(context_settings=mk_cli_context_settings())`

    See `init_cli_ctx` which depends on this.
    """

    obj_d = mk_cli_db_obj_d(mk_db, db_key)

    return dict(
        obj=obj_d,
        # It it also possible to customize cli default values from here.
        # <https://click.palletsprojects.com/en/7.x/commands/#overriding-defaults>
        # default_map
    )


def get_cli_ctx_db(ctx: click.Context) -> CliCtxDbInterface:
    out = get_cli_ctx_db_base(ctx)
    assert isinstance(out, CliCtxDbInterface)
    return out


@dataclass
class CliCtx:
    """This is the cli context we have access to when
        running commands from this cli.
    """
    KEY = "nsf_ssh_auth_dir_cli"

    db: CliCtxDbInterface

    # The *ssh auth dir* over which to operate.
    repo: SshAuthDirRepo
    # The current user's id if available.
    user_id: Optional[str]


def init_cli_ctx(
        ctx: click.Context,
        repo: Union[SshAuthDirRepo, Path],
        user_id: Optional[str]
) -> CliCtx:
    # Make sure the provided context db was of the proper type.
    ctx_db = get_cli_ctx_db(ctx)
    assert isinstance(ctx_db, CliCtxDbInterface)

    if isinstance(repo, Path):
        assert repo.is_absolute()
        repo = mk_ssh_auth_dir_repo(repo)

    init_ctx = CliCtx(ctx_db, repo, user_id)
    return init_ctx_dict_instance(ctx, CliCtx.KEY, init_ctx)


pass_cli_ctx = mk_ctx_dict_pass_decorator(CliCtx.KEY, CliCtx)
