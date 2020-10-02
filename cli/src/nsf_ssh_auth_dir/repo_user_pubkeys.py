from pathlib import Path
from typing import Iterator, Optional, Type

from .file_pubkey import (
    SshPubkeysDb,
    SshPubkeyDumper,
    SshPubkeyFileError,
    SshPubkeyFileAccessError,
    SshPukeyLoader,
    merge_lookup_info,
    load_ssh_pubkey
)
from .policy_repo import SshAuthDirPubkeyPolicy
from .types_base_errors import SshAuthDirRepoError
from .types_pubkey import (
    SshPubKey,
    SshPubKeyFileTemplateVars,
    SshPubKeyLookupInfo,
    SshPubKeyLookupInfoOpt,
)
from .types_users import SshRawUser, SshRawUserDefaults


class SshUserPubkeysRepoError(SshAuthDirRepoError):
    pass


class SshUserPubkeysRepoAccessError(SshUserPubkeysRepoError):
    pass


class SshUserPubkeysRepoFileAccessError(SshUserPubkeysRepoAccessError):
    pass


def get_user_pubkeys_repo_err_cls_from_pubkey_file_err(
        e: SshPubkeyFileError) -> Type[SshUserPubkeysRepoAccessError]:
    if isinstance(e, SshPubkeyFileAccessError):
        return SshUserPubkeysRepoFileAccessError

    return SshUserPubkeysRepoAccessError


class SshUserPubkeysRepo:
    def __init__(
            self,
            sa_root_dir: Path,
            raw: SshRawUser,
            raw_defaults: Optional[SshRawUserDefaults],
            pubkey_policy: SshAuthDirPubkeyPolicy
    ) -> None:
        self._sa_root_dir = sa_root_dir
        self._raw = raw
        self._raw_defaults = raw_defaults
        self._pubkey_policy = pubkey_policy

    @property
    def name(self) -> str:
        return self._raw.name

    def _mk_pubkey_template_vars(self) -> SshPubKeyFileTemplateVars:
        return SshPubKeyFileTemplateVars(self.name)

    def _mk_pubkey_user_lookup_info(self) -> SshPubKeyLookupInfoOpt:
        ft = self._raw.pubkey_file_template
        fsp = self._raw.pubkey_file_search_path

        return SshPubKeyLookupInfoOpt(
            None if ft is None else [ft],
            None if fsp is None else [fsp],
            self._raw.pubkey_file
        )

    def _mk_pubkey_defaults_lookup_info(self) -> SshPubKeyLookupInfo:
        lkups = []

        if self._raw_defaults:
            lkups.append(SshPubKeyLookupInfoOpt(
                self._raw_defaults.pubkey_file_template,
                self._raw_defaults.pubkey_file_search_path,
                None
            ))

        default = self._pubkey_policy.default_lookup_info
        return merge_lookup_info(lkups, default)

    def _mk_db(self) -> SshPubkeysDb:
        return SshPubkeysDb(
            self._mk_pubkey_user_lookup_info(),
            self._mk_pubkey_defaults_lookup_info(),
            self._sa_root_dir,
            self._mk_pubkey_template_vars()
        )

    def _mk_loader(self) -> SshPukeyLoader:
        return SshPukeyLoader(self._mk_db())

    def _mk_dumper(self) -> SshPubkeyDumper:
        return SshPubkeyDumper(self._mk_db())

    @property
    def filenames(self) -> Iterator[Path]:
        db = self._mk_db()
        for fn in db.iter_filenames():
            if not fn.exists():
                continue
            yield fn

    @property
    def selected_filename(self) -> Path:
        loader = self._mk_loader()
        try:
            return loader.selected_filename
        except SshPubkeyFileError as e:
            ECls = get_user_pubkeys_repo_err_cls_from_pubkey_file_err(e)
            raise ECls(str(e)) from e

    @property
    def default_filename(self) -> Path:
        loader = self._mk_loader()
        try:
            return loader.default_filename
        except SshPubkeyFileError as e:
            ECls = get_user_pubkeys_repo_err_cls_from_pubkey_file_err(e)
            raise ECls(str(e)) from e

    @property
    def selected(self) -> SshPubKey:
        loader = self._mk_loader()
        try:
            return loader.load_selected()
        except SshPubkeyFileError as e:
            ECls = get_user_pubkeys_repo_err_cls_from_pubkey_file_err(e)
            raise ECls(str(e)) from e

    @property
    def default(self) -> SshPubKey:
        loader = self._mk_loader()
        try:
            return loader.load_default()
        except SshPubkeyFileError as e:
            ECls = get_user_pubkeys_repo_err_cls_from_pubkey_file_err(e)
            raise ECls(str(e)) from e

    @default.setter
    def default(self, pubkey: SshPubKey) -> None:
        dumper = self._mk_dumper()

        try:
            dumper.dump_default(pubkey)
        except SshPubkeyFileError as e:
            ECls = get_user_pubkeys_repo_err_cls_from_pubkey_file_err(e)
            raise ECls(str(e)) from e

    def __iter__(self) -> Iterator[SshPubKey]:
        for fn in self.filenames:
            yield load_ssh_pubkey(fn)

    def rm_all(self) -> None:
        for fn in self.filenames:
            fn.unlink()

            # Attempt to cleanup empty pubkey dir
            # if possible.
            try:
                fn.parent.rmdir()
            except OSError:
                pass
