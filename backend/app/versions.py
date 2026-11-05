"""Version comparison that handles real-world formats.

Examples: 2.4.49, 1.0.2u (OpenSSL letters), 8.0p1 (OpenSSH), 15.2(7)E3 (Cisco),
21.001.20135 (Adobe), 11.0.1.1261 (Veeam).
"""

import re

_TOKEN = re.compile(r"\d+|[a-zA-Z]+")


def parse_version(version: str) -> tuple:
    # Numbers compare as numbers. Letter suffixes compare by length, then
    # alphabetically, so OpenSSL's 1.0.2z < 1.0.2za < 1.0.2zd works.
    parts = []
    for token in _TOKEN.findall(version or ""):
        if token.isdigit():
            parts.append((0, int(token), ""))
        else:
            parts.append((1, len(token), token.lower()))
    # Drop trailing zeros so 2.4 == 2.4.0
    while parts and parts[-1] == (0, 0, ""):
        parts.pop()
    return tuple(parts)


def in_range(
    version: str,
    min_version: str | None,
    min_inclusive: bool,
    max_version: str | None,
    max_inclusive: bool,
) -> bool:
    v = parse_version(version)
    if not v:
        return False
    if min_version:
        lo = parse_version(min_version)
        if v < lo or (v == lo and not min_inclusive):
            return False
    if max_version:
        hi = parse_version(max_version)
        if v > hi or (v == hi and not max_inclusive):
            return False
    return True
