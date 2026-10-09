#!/usr/bin/env python3
"""Check that cargo-about accepts exactly the licenses cargo-deny allows, in the same order.

`.cargo/deny.toml` `[licenses] allow` is the policy;
`.cargo/about.toml` `accepted` renders THIRD_PARTY_LICENSES.md of a release and must not
drift from it. Prints both lists and exits 1 when they differ.

Runs on any Python 3; the parser covers the one shape both files use: a
`key = [` line, then one quoted string per line, with `#` comments, up to `]`.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENY = ROOT / ".cargo" / "deny.toml"
ABOUT = ROOT / ".cargo" / "about.toml"


def string_list(path, section, key):
    """The strings of `key = [...]` in `[section]` (None: the top level) of `path`."""
    current, values, inside = None, None, False
    for raw in path.read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if inside:
            if line.startswith("]"):
                return values
            values.extend(re.findall(r'"([^"]+)"', line))
            continue
        header = re.fullmatch(r"\[([\w.-]+)\]", line)
        if header:
            current = header.group(1)
        elif current == section and re.fullmatch(rf"{re.escape(key)}\s*=\s*\[", line):
            values, inside = [], True
    sys.exit(f"{path}: no multi-line `{key} = [` list in [{section or 'top level'}]")


def main():
    allow = string_list(DENY, "licenses", "allow")
    accepted = string_list(ABOUT, None, "accepted")
    if allow != accepted:
        print(f"{DENY.relative_to(ROOT)} [licenses] allow: {allow}")
        print(f"{ABOUT.relative_to(ROOT)} accepted:          {accepted}")
        print("the two license lists must be equal, in the same order")
        sys.exit(1)


if __name__ == "__main__":
    main()
