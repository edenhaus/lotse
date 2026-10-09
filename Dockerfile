# The release image: the static binary and nothing else, for a host image's Dockerfile to take
# with `COPY --from=ghcr.io/<owner>/lotse:<version>@sha256:<digest> /lotse /bin/lotse`.
#
# It packages binaries built elsewhere and compiles nothing: scripts/image.sh (`mise run image`,
# release.yml) stages one per platform as <os>/<arch>/lotse in the build context. Since nothing
# runs inside the image, building the foreign platform needs no emulator.
FROM scratch
ARG TARGETPLATFORM
COPY --chmod=0755 ${TARGETPLATFORM}/lotse /lotse
ENTRYPOINT ["/lotse"]
