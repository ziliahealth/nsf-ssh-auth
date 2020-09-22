import click
from pathlib import Path
from typing import Optional
from dataclasses import dataclass


@dataclass
class CliCtx:
    # The *ssh auth dir* over which to operate.
    cwd: Path
    # The current user's id if available.
    user_id: Optional[str]

    @classmethod
    def mk_default(cls) -> 'CliCtx':
        return cls(
            cwd=Path.cwd(),
            user_id=None
        )


def init_cli_ctx(
        ctx: click.Context, init_ctx: CliCtx
) -> CliCtx:
    assert ctx.obj is None
    ctx.obj = init_ctx
    return init_ctx


pass_init_ctx = click.make_pass_decorator(CliCtx)
