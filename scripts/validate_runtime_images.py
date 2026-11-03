#!/usr/bin/env python3
"""Fail closed unless every cAdvisor build/runtime image is digest-pinned."""

from __future__ import annotations

import os
import re

IMAGE = re.compile(
    r"^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*(?::(?P<port>[0-9]{1,5}))?/)?"
    r"[a-z0-9]+(?:[._-][a-z0-9]+)*"
    r"(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[0-9a-f]{64}$"
)
REQUIRED = (
    "GO_BUILDER_IMAGE",
    "PROXY_RUNTIME_IMAGE",
    "CADVISOR_BASE_IMAGE",
    "CODESTRA_CADVISOR_PROXY_IMAGE",
    "CODESTRA_CADVISOR_IMAGE",
)


def valid_image(value: str) -> bool:
    match = IMAGE.fullmatch(value)
    if match is None:
        return False
    port = match.group("port")
    return port is None or 1 <= int(port) <= 65535


def validate(values: dict[str, str]) -> None:
    invalid = [name for name in REQUIRED if not valid_image(values.get(name, ""))]
    if invalid:
        raise SystemExit(
            "invalid or mutable cAdvisor image identities: " + ", ".join(invalid)
        )


def main() -> None:
    validate(dict(os.environ))
    print("CADVISOR_RUNTIME_IMAGE_IDENTITIES=PASS")


if __name__ == "__main__":
    main()
