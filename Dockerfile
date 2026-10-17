# The release image. A host image takes the binary alone:
#
#   COPY --from=ghcr.io/<owner>/lotse:<version>@sha256:<digest> /lotse /bin/lotse
#
# Or it runs as it is, with its control API over mutual TLS:
#
#   docker run -d --name lotse --network host -v lotse-data:/data \
#     -e LOTSE_CONTROL_LISTEN='[::]:18557' ghcr.io/<owner>/lotse:<version>@sha256:<digest>
#   docker logs lotse                   # the first client's pairing code
#   docker exec lotse /lotse pair       # another one-time code
#
# Host networking, because the ICE candidates are the container's own addresses. It starts as
# root and drops to 65534:65534 after binding.
FROM scratch
LABEL org.opencontainers.image.title="lotse" \
      org.opencontainers.image.description="Memory-safe media daemon for IP cameras." \
      org.opencontainers.image.url="https://github.com/edenhaus/lotse" \
      org.opencontainers.image.source="https://github.com/edenhaus/lotse" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"
ARG TARGETARCH
COPY --chmod=0755 target/image/${TARGETARCH}/lotse /lotse
# Empty directories with the mode `serve` checks. scratch has no mkdir, so COPY makes them, and
# --exclude=* leaves the binary out of them.
COPY --chmod=0700 --exclude=* target/image/${TARGETARCH}/ /run/lotse/
COPY --chmod=0700 --exclude=* target/image/${TARGETARCH}/ /data/
ENV LOTSE_SOCKET=/run/lotse/lotse.sock \
    LOTSE_DATA_DIR=/data
EXPOSE 18556/udp 18556/tcp 18557/tcp
ENTRYPOINT ["/lotse"]
CMD ["serve"]
