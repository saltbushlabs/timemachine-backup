FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
COPY templates ./templates
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /timemachine .

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends samba samba-vfs-modules avahi-daemon tini \
 && rm -rf /var/lib/apt/lists/* /etc/avahi/services/* \
 && groupadd -g 1000 tmbackup \
 && useradd -u 1000 -g 1000 -M -d /nonexistent -s /usr/sbin/nologin tmbackup
COPY rootfs/ /
COPY --from=build /timemachine /usr/local/bin/timemachine
VOLUME ["/backups", "/config"]
HEALTHCHECK --interval=30s --timeout=10s --start-period=20s CMD ["timemachine", "healthcheck"]
ENTRYPOINT ["tini", "--", "timemachine"]
CMD ["serve"]
