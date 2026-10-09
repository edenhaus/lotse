#!/bin/sh
# The release image (Dockerfile): FROM scratch with /lotse and nothing else, for a host image's
# `COPY --from`.
#
#   scripts/image.sh load [arch]                  one platform into the local Docker as lotse:dev
#   scripts/image.sh push <repository> <version>  both platforms to the registry as one index
#
# The binaries are target/<arch>-unknown-linux-musl/release/lotse for x86_64 (linux/amd64) and
# aarch64 (linux/arm64): `mise run release-build <arch>` on Linux, or the build artifacts in
# release.yml. `load` takes the host's arch unless told otherwise. `push` needs both, tags the
# index with the version only (never `latest`: consumers pin by digest) and writes the
# index digest to target/dist/image-digest. BuildKit adds no SBOM or provenance of its own:
# release.yml attests the image, and the SBOMs are the binaries' (scripts/sbom.py).
set -eu

# The builder for a multi-platform push when the engine's image store cannot hold one (the
# classic store; the containerd store can). Pinned by digest; Renovate updates it.
BUILDKIT="moby/buildkit:v0.33.1@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea"

cd "$(dirname "$0")/.."
CONTEXT=target/image

usage() {
  echo "usage: scripts/image.sh load [x86_64|aarch64] | push <repository> <version>" >&2
  exit 2
}

platform_of() {
  case "$1" in
    x86_64 | amd64) echo linux/amd64 ;;
    aarch64 | arm64) echo linux/arm64 ;;
    *) echo "no release target for arch $1" >&2; exit 2 ;;
  esac
}

# Copies each arch's binary to <os>/<arch>/lotse in the build context and sets PLATFORMS.
stage() {
  rm -rf "$CONTEXT"
  PLATFORMS=""
  for arch in "$@"; do
    platform="$(platform_of "$arch")"
    case "$platform" in linux/amd64) arch=x86_64 ;; linux/arm64) arch=aarch64 ;; esac
    bin="target/$arch-unknown-linux-musl/release/lotse"
    [ -f "$bin" ] || { echo "$bin is missing: mise run release-build $arch (Linux)" >&2; exit 1; }
    mkdir -p "$CONTEXT/$platform"
    cp "$bin" "$CONTEXT/$platform/lotse"
    PLATFORMS="${PLATFORMS:+$PLATFORMS,}$platform"
  done
}

# The image's timestamps are the commit's, so the same binaries give the same image.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
export SOURCE_DATE_EPOCH
REVISION="$(git rev-parse HEAD)"
DESCRIPTION="Media daemon: RTSP cameras to browsers over WebRTC."

case "${1:-}" in
  load)
    [ $# -le 2 ] || usage
    stage "${2:-$(uname -m)}"
    docker buildx build \
      --platform "$PLATFORMS" \
      --provenance=false --sbom=false \
      --label "org.opencontainers.image.revision=$REVISION" \
      --tag lotse:dev --load \
      --file Dockerfile "$CONTEXT"
    echo "lotse:dev ($PLATFORMS); try: docker run --rm lotse:dev --version"
    ;;
  push)
    [ $# -eq 3 ] || usage
    repository="$2" version="$3"
    # ghcr.io links the package to the repository through this label; Actions sets both variables.
    : "${GITHUB_REPOSITORY:?push needs GITHUB_REPOSITORY (owner/name), as GitHub Actions sets it}"
    SOURCE="${GITHUB_SERVER_URL:-https://github.com}/$GITHUB_REPOSITORY"
    stage x86_64 aarch64
    builder=""
    if ! docker info --format '{{.DriverStatus}}' | grep -q io.containerd.snapshotter; then
      docker buildx inspect lotse-release >/dev/null 2>&1 ||
        docker buildx create --name lotse-release --driver docker-container --driver-opt "image=$BUILDKIT" >/dev/null
      builder="--builder=lotse-release"
    fi
    mkdir -p target/dist
    # $builder is empty or one word; unquoted so that empty passes nothing.
    # shellcheck disable=SC2086
    docker buildx build $builder \
      --platform "$PLATFORMS" \
      --provenance=false --sbom=false \
      --label "org.opencontainers.image.revision=$REVISION" \
      --label "org.opencontainers.image.source=$SOURCE" \
      --label "org.opencontainers.image.version=$version" \
      --label "org.opencontainers.image.licenses=MIT OR Apache-2.0" \
      --annotation "index:org.opencontainers.image.source=$SOURCE" \
      --annotation "index:org.opencontainers.image.description=$DESCRIPTION" \
      --annotation "index:org.opencontainers.image.licenses=MIT OR Apache-2.0" \
      --tag "$repository:$version" \
      --output type=image,push=true,unpack=false,oci-mediatypes=true,rewrite-timestamp=true \
      --metadata-file "$CONTEXT/metadata.json" \
      --file Dockerfile "$CONTEXT"
    digest="$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["containerimage.digest"])' "$CONTEXT/metadata.json")"
    echo "$digest" > target/dist/image-digest
    echo "$repository:$version@$digest"
    ;;
  *) usage ;;
esac
