#!/usr/bin/env python3
"""Write the CycloneDX SBOM of the `lotse` binary for one release target.

`mise run sbom` and release.yml call it:

    scripts/sbom.py <target> <output>

cargo-cyclonedx writes the document from `cargo metadata`, whose resolve does not
apply resolver 2's feature split by target and dependency kind: on 2026-10-06 it
listed 25 crate versions the binary compiles on neither target (x509-parser,
defmt, indexmap and their dependencies, reachable only through optional features
nothing turns on in that build). This script keeps the components that `cargo tree` resolves
for the target with the binary's default features, which is the build's own
resolver, and the dependency edges between them, and prints what it dropped.

SOURCE_DATE_EPOCH, when unset, is the commit time, so the document's timestamp
is that of the source, not of the run. Runs on any Python 3.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "crates" / "lotse" / "Cargo.toml"


def cyclonedx(target, env):
    """Run cargo-cyclonedx and return the binary's document, removing every file it wrote."""
    pattern = f"*_bin_{target}.cdx.json"
    subprocess.run(
        [
            "cargo", "cyclonedx",
            "--manifest-path", str(MANIFEST),
            "--format", "json",
            "--spec-version", "1.5",
            "--target", target,
            "--no-build-deps",
            "--describe", "binaries",
            "--target-in-filename",
        ],
        cwd=ROOT,
        env=env,
        check=True,
    )
    # It writes one file per binary of every workspace member, next to each manifest.
    written = sorted((ROOT / "crates").glob(f"*/{pattern}"))
    document = None
    for path in written:
        if path.parent == MANIFEST.parent and path.name == f"lotse_bin_{target}.cdx.json":
            document = json.loads(path.read_text())
        path.unlink()
    if document is None:
        sys.exit(f"cargo cyclonedx wrote no SBOM for the lotse binary on {target}")
    return document


def resolved(target):
    """The (name, version) of every crate the binary compiles for `target`, per `cargo tree`."""
    out = subprocess.run(
        [
            "cargo", "tree", "--locked",
            "--package", "lotse",
            "--target", target,
            "--edges", "normal",
            "--prefix", "none",
            "--format", "{p}",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    crates = set()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 2 and fields[1].startswith("v"):
            crates.add((fields[0], fields[1][1:]))
    if not crates:
        sys.exit(f"cargo tree resolved no crates for lotse on {target}")
    return crates


def prune(document, crates):
    """Drop the components outside `crates` and every edge that touches one; return their names."""
    kept, dropped = [], []
    for component in document.get("components", []):
        if (component["name"], component["version"]) in crates:
            kept.append(component)
        else:
            dropped.append(component)
    document["components"] = kept
    refs = {component["bom-ref"] for component in kept}
    refs.add(document["metadata"]["component"]["bom-ref"])
    dependencies = []
    for dependency in document.get("dependencies", []):
        if dependency["ref"] in refs:
            depends_on = [ref for ref in dependency.get("dependsOn", []) if ref in refs]
            dependencies.append({**dependency, "dependsOn": depends_on})
    document["dependencies"] = dependencies
    return sorted(f"{c['name']} {c['version']}" for c in dropped)


def main():
    if len(sys.argv) != 3:
        sys.exit("usage: scripts/sbom.py <target> <output>")
    target, output = sys.argv[1], Path(sys.argv[2])
    env = dict(os.environ)
    if "SOURCE_DATE_EPOCH" not in env:
        env["SOURCE_DATE_EPOCH"] = subprocess.run(
            ["git", "log", "-1", "--format=%ct"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    crates = resolved(target)  # first: `--locked` fails on a stale lockfile before cargo-cyclonedx could update it
    document = cyclonedx(target, env)
    dropped = prune(document, crates)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2) + "\n")
    print(f"{output}: {len(document['components'])} components for {target}")
    if dropped:
        print(f"  not compiled for {target}, left out: {', '.join(dropped)}")


if __name__ == "__main__":
    main()
