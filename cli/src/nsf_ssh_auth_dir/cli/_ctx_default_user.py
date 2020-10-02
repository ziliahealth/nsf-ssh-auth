from abc import abstractmethod
from typing import Optional, List

import click

from ._ctx import CliCtxDbBase, get_cli_ctx_db_base


class CliCtxDbWDefaultUser(CliCtxDbBase):
    @abstractmethod
    def get_default_user_id(
            self, ctx: click.Context, args: List[str]) -> Optional[str]:
        pass


def get_cli_ctx_db_w_default_user(ctx: click.Context) -> CliCtxDbWDefaultUser:
    out = get_cli_ctx_db_base(ctx)
    assert isinstance(out, CliCtxDbWDefaultUser)
    return out
