#!/bin/sh
# The release image's vulnerability scan with Grype: CI's Rootless Podman job runs it on the image
# it built, release.yml on the pushed image before attesting it.
#
# The image is scratch and one static binary, so what Grype can match is the crates the binary
# links, which it reads from the dependency list cargo-auditable embeds (`mise run release-build`).
# A binary without that list would scan clean whatever it links, so fewer than $MIN_CRATES crates
# found is a failure too. Fails on a HIGH or CRITICAL vulnerability that has a fix.
#
# Usage: scripts/scan-image.sh <grype source> [platform] [sarif file]
#   e.g. oci-archive:lotse.tar, or registry:ghcr.io/<owner>/lotse@sha256:<digest> linux/arm64
set -eu

SOURCE="${1:?usage: $0 <grype source> [platform] [sarif file]}"
PLATFORM="${2:-}"
SARIF="${3:-}"
MIN_CRATES=100 # the binary links about 300

out="$(mktemp -d)"
set -- "$SOURCE" --only-fixed --fail-on high --output table --output "cyclonedx-json=$out/scan.cdx.json"
[ -z "$PLATFORM" ] || set -- "$@" --platform "$PLATFORM"
[ -z "$SARIF" ] || set -- "$@" --output "sarif=$SARIF"
status=0
grype "$@" || status=$?

crates="$(jq '[.components[]? | select((.purl // "") | startswith("pkg:cargo/"))] | length' "$out/scan.cdx.json")"
echo "$SOURCE${PLATFORM:+ ($PLATFORM)}: $crates crates read from the binary"
if [ "$crates" -lt "$MIN_CRATES" ]; then
  echo "FAIL: fewer than $MIN_CRATES crates: is the binary built with cargo auditable?" >&2
  exit 1
fi
exit "$status"
