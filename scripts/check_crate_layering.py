#!/usr/bin/env python3
"""Enforce the crate layering in .cargo/layering.toml against `cargo metadata`.

The intended dependency graph lives in the TOML file so it can be written ahead
of the code. Every direct dependency edge between workspace crates must be
listed there, a restricted external crate may only be a direct dependency of
its owners, and a dev-only crate may never be a normal or build dependency. Prints one line per violation and exits 1.

Runs on any Python 3; the config parser covers exactly the TOML subset the file
uses: `[section]` headers and `key = ["a", "b"]` lines, with `#` comments.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / ".cargo" / "layering.toml"


def parse(text):
    """Parse the layering file into {section: {key: [values]}}."""
    sections, current = {}, None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        header = re.fullmatch(r"\[([\w.-]+)\]", line)
        if header:
            current = sections.setdefault(header.group(1), {})
            continue
        entry = re.fullmatch(r"([\w.-]+)\s*=\s*\[(.*)\]", line)
        if entry is None or current is None:
            sys.exit(f"{CONFIG}: cannot parse line: {raw!r}")
        current[entry.group(1)] = re.findall(r'"([^"]+)"', entry.group(2))
    return sections


def metadata():
    """Workspace members and their direct dependencies, offline."""
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {pkg["name"]: pkg for pkg in json.loads(out)["packages"]}


def main():
    config = parse(CONFIG.read_text())
    dependents = config.get("dependents", {})
    dev_only = set(config.get("dev-only", {}).get("crates", []))
    external = config.get("external", {})
    members = metadata()
    errors = []
    for name, pkg in sorted(members.items()):
        for dep in pkg["dependencies"]:
            target, kind = dep["name"], dep["kind"] or "normal"
            if target in members:
                if name not in dependents.get(target, []):
                    errors.append(
                        f"{name} -> {target} ({kind}): edge not allowed; add it to "
                        f"[dependents] in {CONFIG.name} if the edge is intended"
                    )
            elif target in external and name not in external[target]:
                owners = ", ".join(external[target])
                errors.append(f"{name} -> {target} ({kind}): only {owners} may depend on {target} directly")
            if target in dev_only and kind != "dev":
                errors.append(f"{name} -> {target} ({kind}): {target} may only be a dev-dependency")
    for error in errors:
        print(f"layering: {error}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
