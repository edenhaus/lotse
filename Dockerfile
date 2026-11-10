# The release image: the static binary on scratch, run as uid and gid 65532 from the start, so a
# rootless engine maps it from its default subordinate ids and the daemon needs no capability.
# A host image takes the binary alone:
#
#   COPY --from=ghcr.io/<owner>/lotse:<version>@sha256:<digest> /lotse /bin/lotse
#
# Or it runs as it is, rootless, read-only and without a capability (README.md, "Running in a
# container", has the same as a Podman Quadlet unit, and says why no host network is needed):
#
#   podman run -d --name lotse --read-only --cap-drop=all --security-opt=no-new-privileges \
#     --tmpfs /run/lotse:rw,mode=0700,uid=65532,gid=65532 -v lotse-data:/data \
#     -p 30415:30415/udp -p 30415:30415/tcp -p 18557:18557/tcp \
#     -e LOTSE_WEBRTC_ADVERTISE=<the host's LAN address> -e LOTSE_SANDBOX=require \
#     -e LOTSE_CONTROL_LISTEN='[::]:18557' --pids-limit=512 --memory=1g \
#     ghcr.io/<owner>/lotse:<version>@sha256:<digest>
#   podman logs lotse                  # the first client's pairing code
#   podman exec lotse /lotse pair      # another one-time code
#
# Started as root instead (`--user 0`), it needs CAP_SETUID and CAP_SETGID, binds, and drops to
# LOTSE_USER and LOTSE_GROUP, the same 65532.
# The two directories of the daemon's account, with the mode `serve` checks: scratch has no mkdir,
# and COPY sets the mode of a directory it makes differently in BuildKit and Buildah, so a stage
# makes them and the image takes them with their owner and mode. On the build's own platform: it
# runs no code of the target's, and nothing of busybox reaches the image.
FROM --platform=$BUILDPLATFORM mirror.gcr.io/library/busybox:1.37.0@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec AS dirs
RUN mkdir -p /rootfs/run/lotse /rootfs/data \
 && chown 65532:65532 /rootfs/run/lotse /rootfs/data \
 && chmod 0700 /rootfs/run/lotse /rootfs/data

FROM scratch
LABEL org.opencontainers.image.title="lotse" \
      org.opencontainers.image.description="Memory-safe media daemon for IP cameras." \
      org.opencontainers.image.url="https://github.com/edenhaus/lotse" \
      org.opencontainers.image.source="https://github.com/edenhaus/lotse" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
ARG TARGETARCH
# Root's, so the account the daemon runs as cannot change it.
COPY --chmod=0755 target/image/${TARGETARCH}/lotse /lotse
# /run root's 0755, /run/lotse and /data the account's 0700. A volume made on /data takes their
# owner and mode; --read-only needs a tmpfs on /run/lotse.
COPY --from=dirs /rootfs/ /
ENV LOTSE_SOCKET=/run/lotse/lotse.sock \
    LOTSE_DATA_DIR=/data \
    LOTSE_USER=65532 \
    LOTSE_GROUP=65532
USER 65532:65532
EXPOSE 30415/udp 30415/tcp 18557/tcp
ENTRYPOINT ["/lotse"]
CMD ["serve"]
