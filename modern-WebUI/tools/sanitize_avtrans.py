#!/usr/bin/env python3
"""Sanitize PM3000 Avtrans XML captures for safe fixture review."""

from __future__ import annotations

import argparse
import os
import re
import stat
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from pathlib import Path


USERNAME_HINTS = ("username", "loginuser")
SECRET_HINTS = (
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "credential",
    "authorization",
    "privatekey",
    "certificate",
    "community",
)
NETWORK_HINTS = ("hostname", "server", "ipaddress", "address", "domain", "gateway", "nameserver", "dns")
OPERATOR_ASSIGNED_PARAMETER_IDS = {"name", "serialnumber"}
PRIVATE_IPV4 = re.compile(
    r"\b(?:10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})\b"
)
PRIVATE_HOSTNAME = re.compile(r"\b(?:[A-Za-z0-9_-]+\.)+(?:local|lan|internal|home|mdn)\b", re.IGNORECASE)
MAX_INPUT_BYTES = 1024 * 1024
MAX_XML_DEPTH = 32


class _RejectingTreeBuilder(ET.TreeBuilder):
    def doctype(self, name: str, public_id: str | None, system_id: str | None) -> None:
        raise ValueError("DTD and entity declarations are not accepted")


def _normalized_identifier(value: str) -> str:
    return "".join(character for character in value.lower() if character.isalnum())


def _local_name(value: str) -> str:
    return value.rsplit("}", 1)[-1]


def _attribute_by_local_name(element: ET.Element, wanted: str) -> str:
    for name, value in element.attrib.items():
        if _local_name(name) == wanted:
            return value
    return ""


def _replacement_for_identifier(value: str) -> str | None:
    normalized = _normalized_identifier(value)
    if any(hint in normalized for hint in USERNAME_HINTS) or normalized == "user":
        return "[REDACTED-USERNAME]"
    if any(hint in normalized for hint in SECRET_HINTS + NETWORK_HINTS):
        return "[REDACTED]"
    return None


def _scrub_literals(value: str | None, explicit_values: tuple[str, ...]) -> str | None:
    if value is None:
        return None
    scrubbed = value
    for explicit_value in explicit_values:
        scrubbed = scrubbed.replace(explicit_value, "[REDACTED]")
    scrubbed = PRIVATE_IPV4.sub("[REDACTED]", scrubbed)
    return PRIVATE_HOSTNAME.sub("[REDACTED]", scrubbed)


def _validate_depth(root: ET.Element) -> None:
    stack = [(root, 1)]
    while stack:
        element, depth = stack.pop()
        if depth > MAX_XML_DEPTH:
            raise ValueError("capture exceeds the XML depth limit")
        stack.extend((child, depth + 1) for child in element)


def _redact_subtree(element: ET.Element, replacement: str, preserve_root_attributes: bool) -> None:
    for descendant in element.iter():
        if descendant.text is not None and descendant.text.strip():
            descendant.text = replacement
        if descendant.tail is not None and descendant.tail.strip():
            descendant.tail = replacement
        for name in descendant.attrib:
            preserve = descendant is element and preserve_root_attributes and _local_name(name) in {"id", "structure"}
            if not preserve:
                descendant.set(name, replacement)


def _read_regular_nofollow(path: Path) -> bytes:
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise ValueError("this platform cannot safely reject symlink input")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("input must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = -1
            return stream.read(MAX_INPUT_BYTES + 1)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def sanitize_xml(source: bytes, explicit_values: Iterable[str] = ()) -> str:
    """Return structurally equivalent XML with session and login values redacted."""
    if len(source) > MAX_INPUT_BYTES:
        raise ValueError("capture exceeds the 1 MiB size limit")

    redactions = tuple(sorted((value for value in explicit_values if value), key=len, reverse=True))
    upper_source = source.upper()
    if b"<!DOCTYPE" in upper_source or b"<!ENTITY" in upper_source:
        raise ValueError("DTD and entity declarations are not accepted")

    root = ET.fromstring(source, parser=ET.XMLParser(target=_RejectingTreeBuilder()))
    if root.tag != "avtrans":
        raise ValueError("expected avtrans root element")
    _validate_depth(root)
    login_parameters = {
        id(parameter)
        for section in root.iter()
        if _local_name(section.tag) == "section" and _attribute_by_local_name(section, "structure").lower() == "login"
        for parameter in section.iter()
        if _local_name(parameter.tag) == "parameter"
    }

    for element in root.iter():
        element.text = _scrub_literals(element.text, redactions)
        element.tail = _scrub_literals(element.tail, redactions)
        for name, value in element.attrib.items():
            replacement = _replacement_for_identifier(_local_name(name))
            element.set(name, replacement or _scrub_literals(value, redactions) or "")

        tag = _local_name(element.tag)
        if tag == "sid":
            _redact_subtree(element, "[REDACTED-SID]", preserve_root_attributes=False)

        if tag != "parameter":
            replacement = _replacement_for_identifier(tag)
            if replacement is not None:
                _redact_subtree(element, replacement, preserve_root_attributes=False)
            continue

        parameter_id = _normalized_identifier(_attribute_by_local_name(element, "id"))
        replacement = _replacement_for_identifier(parameter_id)
        if replacement is None and parameter_id in OPERATOR_ASSIGNED_PARAMETER_IDS:
            replacement = "[REDACTED-NAME]"
        if replacement is None:
            replacement = _replacement_for_identifier(_attribute_by_local_name(element, "structure"))
        if replacement is None and id(element) in login_parameters:
            replacement = "[REDACTED]"

        if replacement is not None:
            _redact_subtree(element, replacement, preserve_root_attributes=True)

    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode") + "\n"


def _write_private_atomic(path: Path, content: str) -> None:
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("output must be a regular file path")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, path)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="raw Avtrans XML capture")
    parser.add_argument("output", type=Path, help="separate sanitized XML output")
    parser.add_argument("--redact", action="append", default=[], metavar="VALUE", help="additional literal to redact")
    arguments = parser.parse_args(argv)

    try:
        if arguments.input.resolve() == arguments.output.resolve():
            raise ValueError("input and output must be different files")
        source = _read_regular_nofollow(arguments.input)
        sanitized = sanitize_xml(source, explicit_values=arguments.redact)
        _write_private_atomic(arguments.output, sanitized)
    except (OSError, ValueError, ET.ParseError) as error:
        parser.exit(1, f"sanitize-avtrans: {error}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
