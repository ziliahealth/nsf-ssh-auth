import os
import re
from pathlib import Path
from typing import Iterable, Iterator, Optional

from ._content_persistance_tools import mk_parent_dirs_opt
from .types_base_errors import SshAuthDirFileError
from .types_pubkey import (SshPubKey, SshPubKeyFileTemplateVars,
                           SshPubKeyLookupInfo, SshPubKeyLookupInfoOpt)


class SshPubkeyFileError(SshAuthDirFileError):
    pass


class SshPubkeyFileAccessError(SshPubkeyFileError):
    pass


class SshPubkeyFileUnreachableUsingProvidedLookupInfoError(
        SshPubkeyFileAccessError):
    pass


class SshPubkeyFileNotFoundUsingProvidedLookupInfoError(
        SshPubkeyFileAccessError):
    def __init__(
            self,
            lookup: SshPubKeyLookupInfo,
            location_qualifier: str
    ) -> None:
        ts_str = ", ".join(f"'{ft}'" for ft in lookup.file_template)
        sp_str = ", ".join(f"'{sp}'" for sp in lookup.file_search_path)

        msg = (
            f"Cannot locate any valid pubkey *{location_qualifier}* location. "
            f"Looked for basename templates {{{ts_str}}} "
            f"in search path '{sp_str}' to no avail."
        )

        super().__init__(msg)
    pass


def load_ssh_pubkey(filename: Path) -> SshPubKey:
    try:
        with open(filename) as in_f:
            return SshPubKey(
                text_lines=list(in_f)
            )
    except FileNotFoundError as e:
        raise SshPubkeyFileAccessError(str(e)) from e


def get_user_home_ssh_dir() -> Path:
    return Path.home().joinpath(".ssh")


def get_user_home_ssh_pubkey() -> Path:
    return get_user_home_ssh_dir().joinpath("id_rsa.pub")


def load_user_home_ssh_pubkey() -> SshPubKey:
    return load_ssh_pubkey(get_user_home_ssh_pubkey())


def dump_ssh_pubkey(pubkey: SshPubKey, out_filename: Path) -> None:
    with open(out_filename, "w") as out_f:
        out_f.writelines(pubkey.text_lines)


def expand_file_template_vars(
        file_template: str,
        template_vars: SshPubKeyFileTemplateVars
) -> str:
    out_basename = file_template.replace(
        "${ssh-user.name}", template_vars.username)

    # Make sure no remaining / unexpanded variable remain
    # in the file template.
    assert re.search(r"\${[^}]*}", out_basename) is None
    return out_basename


def get_default_pubkey_file_template() -> str:
    return "${ssh-user.name}.pub"


def get_default_pubkey_rdir() -> Path:
    return Path("./public-keys")


def get_default_lookup_info() -> SshPubKeyLookupInfo:
    return SshPubKeyLookupInfo(
        [
            get_default_pubkey_file_template()
        ],
        [
            get_default_pubkey_rdir()
        ],
        None
    )


def _canonicalize_potentially_rel_path(
    dir: Path,
    ssh_auth_dir_root: Path
) -> Path:
    if dir.is_absolute():
        return dir

    return ssh_auth_dir_root.joinpath(dir)


def canonicalize_lookup_info(
    lookup: SshPubKeyLookupInfo,
    ssh_auth_dir_root: Path,
    template_vars: SshPubKeyFileTemplateVars
) -> SshPubKeyLookupInfo:
    """Expand the template variables and ensure that paths are made absolute.
    """
    ad_root = ssh_auth_dir_root
    expd = expand_file_template_vars
    canz_path = _canonicalize_potentially_rel_path
    return SshPubKeyLookupInfo(
        [expd(ft, template_vars) for ft in lookup.file_template],
        [canz_path(sp, ad_root) for sp in lookup.file_search_path],
        canz_path(lookup.file, ad_root) if lookup.file is not None else None
    )


def merge_lookup_info(
    in_lookups: Iterable[SshPubKeyLookupInfoOpt],
    default: Optional[SshPubKeyLookupInfo] = None
) -> SshPubKeyLookupInfo:
    """Merge a listing of lookup info.

    A rightmost entry field overrides lefmost when
    specified.
    """
    if default is None:
        out = get_default_lookup_info()
    else:
        out = default

    for lkup in in_lookups:
        if lkup.file is not None:
            out.file = lkup.file

        if lkup.file_template is not None:
            out.file_template = lkup.file_template

        if lkup.file_search_path is not None:
            out.file_search_path = lkup.file_search_path

    return out


class SshPubkeysDb:
    def __init__(
        self,
        user_lookup: SshPubKeyLookupInfoOpt,
        default_lookup: SshPubKeyLookupInfo,
        ssh_auth_dir_root: Path,
        template_vars: SshPubKeyFileTemplateVars
    ) -> None:
        self._user_lookup = user_lookup
        self._uncanonical_lookup = merge_lookup_info(
            [user_lookup], default_lookup
        )
        self._lookup = canonicalize_lookup_info(
            self._uncanonical_lookup,
            ssh_auth_dir_root,
            template_vars
        )
        self._ssh_auth_dir_root = ssh_auth_dir_root
        self._template_vars = template_vars

    def iter_filenames(self) -> Iterator[Path]:
        for sp in self._lookup.file_search_path:
            assert sp.is_absolute()
            for ft in self._lookup.file_template:
                filename = sp.joinpath(ft)
                yield filename

    def get_selected_filename(
            self) -> Path:
        lookup = self._lookup

        if lookup.file is not None:
            return lookup.file

        for filename in self.iter_filenames():
            if os.access(filename, os.R_OK):
                return filename

        raise SshPubkeyFileNotFoundUsingProvidedLookupInfoError(
            self._lookup, "readable")

    def get_default_filename(self) -> Path:
        lookup = self._lookup

        # When the file is explicitely specified, use this.
        if lookup.file is not None:
            return lookup.file

        pk_basename_template = get_default_pubkey_file_template()
        if self._user_lookup.file_template is not None:
            # When the user specifies a file template, this
            # template becomes part of the default filename.
            u_fts = list(self._user_lookup.file_template)
            assert 1 == len(u_fts)
            pk_basename_template = u_fts[0]

        pk_rdir = get_default_pubkey_rdir()

        if self._user_lookup.file_search_path is not None:
            # When the user specifies a dir in search path, this
            # dir becomes part of the default filename.
            u_sps = list(self._user_lookup.file_search_path)
            assert 1 == len(u_sps)
            pk_rdir = u_sps[0]

        pk_basename = expand_file_template_vars(
            pk_basename_template, self._template_vars)
        assert not pk_rdir.is_absolute()
        pk_dir = self._ssh_auth_dir_root.joinpath(pk_rdir)

        out_filename = pk_dir.joinpath(pk_basename)

        # We make sure that it will be possible for our pubkey to be found.
        if (pk_dir not in lookup.file_search_path
                or pk_basename not in lookup.file_template):
            out_rel_file_template = f"{pk_rdir}/{pk_basename_template}"
            ts_str = ", ".join(
                f"'{ft}'" for ft in self._uncanonical_lookup.file_template)
            sp_str = ", ".join(
                f"'{sp}'" for sp in self._uncanonical_lookup.file_search_path)

            raise SshPubkeyFileUnreachableUsingProvidedLookupInfoError(
                f"Default pubkey location '{out_rel_file_template}' not "
                f"reacheable through search path {{{sp_str}}} using "
                f"file template {{{ts_str}}}."
            )

        return out_filename


class SshPukeyLoader:
    def __init__(
            self,
            pubkey_db: SshPubkeysDb
    ) -> None:
        self._pubkey_db = pubkey_db

    @property
    def default_filename(self) -> Path:
        """Return the filename of the first found writable
            pubkey location according to search path and pattern
            if any.

        Raises:
            SshPubkeyFileNotFoundUsingProvidedLookupInfoError:
                When no writable location for pubkey found.

        Returns:
            The path to the first found pubkey.
        """
        return self._pubkey_db.get_default_filename()

    def load_default(self) -> SshPubKey:
        """Return the first found pubkey
            according to search path and pattern if any.

        Raises:
            SshPubkeyFileNotFoundUsingProvidedLookupInfoError:
                When no pubkey file found.

        Returns:
            The pubkey.
        """
        filename = self.default_filename
        return load_ssh_pubkey(filename)

    @property
    def selected_filename(self) -> Path:
        """Return the filename of the first found pubkey
            according to search path and pattern if any.

        Raises:
            SshPubkeyFileNotFoundUsingProvidedLookupInfoError:
                When no pubkey file found.

        Returns:
            The path to the first found pubkey.
        """
        filename = self._pubkey_db.get_selected_filename()
        return filename

    def load_selected(self) -> SshPubKey:
        """Return the first found pubkey
            according to search path and pattern if any.

        Raises:
            SshPubkeyFileNotFoundUsingProvidedLookupInfoError:
                When no pubkey file found.

        Returns:
            The pubkey.
        """
        filename = self.selected_filename
        return load_ssh_pubkey(filename)


def _mk_parent_dirs_opt(filename: Path, allow: bool) -> None:
    mk_parent_dirs_opt(filename, allow)


class SshPubkeyDumper:
    def __init__(
            self,
            pubkey_db: SshPubkeysDb
    ) -> None:
        self._pubkey_db = pubkey_db

    @property
    def default_filename(self) -> Path:
        """Return the filename of the first found writable
            pubkey location according to search path and pattern
            if any.

        Raises:
            SshPubkeyFileNotFoundUsingProvidedLookupInfoError:
                When no writable location for pubkey found.

        Returns:
            The path to the first found pubkey.
        """
        return self._pubkey_db.get_default_filename()

    def dump_default(self, pubkey: SshPubKey, mk_parent_dirs: bool = True) -> None:
        """Dump the specified pubkey to the first found writable
            location according to search path and pattern
            if any.

        Raises:
            SshPubkeyFileNotFoundUsingProvidedLookupInfoError:
                When no writable location for pubkey found.
        """
        filename = self.default_filename

        _mk_parent_dirs_opt(filename, mk_parent_dirs)
        return dump_ssh_pubkey(pubkey, filename)
