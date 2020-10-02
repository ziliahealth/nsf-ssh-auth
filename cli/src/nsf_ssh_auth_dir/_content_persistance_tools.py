from pathlib import Path
from typing import Dict, Any, Iterator, Tuple, Callable, Union

import json
import yaml


class FileContentError(Exception):
    pass


class FileContentAccessError(FileContentError):
    pass


class FileContentFormatError(FileContentError):
    pass


FileContentPlainT = Dict[str, Any]


def _load_content_from_json_file(
        filename: Path) -> FileContentPlainT:

    try:
        with open(filename) as f:
            # We want to preserve key order. Json already does that.
            out = json.load(f)
    except FileNotFoundError as e:
        raise FileContentAccessError(str(e))
    except json.decoder.JSONDecodeError as e:
        raise FileContentFormatError(f"Not a valid json file: {str(e)}") from e

    assert out is not None
    return out


def _load_content_from_yaml_file(
        filename: Path) -> FileContentPlainT:
    try:
        with open(filename) as f:
            # We want to preserve key order.
            # Yaml already does that on load.
            out = yaml.safe_load(f)
    except FileNotFoundError as e:
        raise FileContentAccessError(str(e))

    assert out is not None
    return out


def load_content_from_file(
        filename: Path) -> FileContentPlainT:
    if ".yaml" == filename.suffix:
        return _load_content_from_yaml_file(filename)

    assert ".json" == filename.suffix
    return _load_content_from_json_file(filename)


def get_field_of_expected_type(
        content: FileContentPlainT,
        field_name: str,
        expected_types: Union[type, Tuple[type, ...]],
        exception_cls: Callable[[str], Exception]) -> Any:
    field_value = content.get(field_name, None)

    if not isinstance(expected_types, tuple):
        expected_types = (expected_types,)

    if not isinstance(field_value, expected_types):
        expected_types_str = ", ".join(t.__name__ for t in expected_types)
        raise exception_cls(
            f"'{field_name}' field not in expected "
            f"type set {{{expected_types_str}}} "
            "but instead was "
            f"found to be of type '{type(field_value).__name__}'."
        )

    assert isinstance(field_value, expected_types)
    return field_value


def get_opt_field_of_expected_type(
        content: FileContentPlainT,
        field_name: str,
        expected_types: Union[type, Tuple[type, ...]],
        exception_cls: Callable[[str], Exception]) -> Any:

    if not isinstance(expected_types, tuple):
        expected_types = (expected_types,)

    return get_field_of_expected_type(
        content, field_name, expected_types + (type(None),), exception_cls)


def get_opt_list_field_of_expected_type(
        content: FileContentPlainT,
        field_name: str,
        expected_types: Union[type, Tuple[type, ...]],
        exception_cls: Callable[[str], Exception]) -> Any:
    if not isinstance(expected_types, tuple):
        expected_types = (expected_types,)

    opt_list = get_field_of_expected_type(
        content, field_name, (list, type(None)), exception_cls)

    if opt_list is None:
        return opt_list

    for idx, x in enumerate(opt_list):
        if not isinstance(x, expected_types):
            expected_types_str = ", ".join(t.__name__ for t in expected_types)
            raise exception_cls(
                f"'{field_name}' list field at index {idx} not in expected "
                f"type set {{{expected_types_str}}} but instead was "
                f"found to be of type '{type(x).__name__}'."
            )

    return opt_list


def _dump_content_to_yaml_file(
        content: FileContentPlainT,
        out_filename: Path
) -> None:
    with open(out_filename, 'w') as of:
        # We want to preserve key order, thus the `sort_keys=False`.
        yaml.safe_dump(content, of, sort_keys=False)


def _dump_content_to_json_file(
        content: FileContentPlainT,
        out_filename: Path
) -> None:
    with open(out_filename, 'w') as of:
        # We want to preserve key order, thus the `sort_keys=False`.
        json.dump(
            content,
            of,
            sort_keys=False,
            indent=2,
            separators=(',', ': ')
        )


def dump_content_to_file(
        content: FileContentPlainT,
        out_filename: Path
) -> None:
    if ".yaml" == out_filename.suffix:
        return _dump_content_to_yaml_file(content, out_filename)

    assert ".json" == out_filename.suffix
    return _dump_content_to_json_file(content, out_filename)


def dump_content_as_yaml_lines(
        content: FileContentPlainT,
) -> Iterator[str]:
    # TODO: Find a way to perform the dump iteratively / in a
    # streaming fashion.
    out_str = yaml.safe_dump(content, sort_keys=False)
    for l in out_str.splitlines(keepends=True):
        yield l


def format_content_as_yaml_str(
        content: FileContentPlainT) -> str:
    if not content:
        return ""

    return "".join(dump_content_as_yaml_lines(content))


def mk_parent_dirs_opt(filename: Path, allow: bool) -> None:
    if not allow:
        return

    filename.parent.mkdir(exist_ok=True, parents=True)


def rm_dict_key(
    d: Dict[str, Any],
    key: str
) -> None:
    try:
        del d[key]
    except KeyError:
        pass


def add_to_dict_lazy(
    d: Dict[str, Any],
    key: str,
    value: Union[Any, Callable[[], Any]],
) -> None:
    d[key] = (value() if callable(value) else value)


def add_cond_to_dict_or_rm_key(
        condition: bool,
        d: Dict[str, Any],
        key: str,
        value: Union[Any, Callable[[], Any]],
) -> None:
    if condition:
        # Allow lazyness.
        add_to_dict_lazy(d, key, value)
    else:
        rm_dict_key(d, key)
