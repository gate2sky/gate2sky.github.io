# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/intergate ./cmd/intergate \
 && mkdir -p /out/data && chmod 700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/intergate /usr/local/bin/intergate
COPY --from=build --chown=65532:65532 /out/data /data
# The configuration and all state live in /data:
#   docker run -it --rm -v intergate:/data IMAGE config   (create the configuration)
#   docker run -d -v intergate:/data -p ... IMAGE         (run it)
ENV INTERGATE_CONFIG=/data/intergate.yaml \
    INTERGATE_DATA_DIR=/data
VOLUME /data
# Plus the range of tcp.ports, if set, over TCP and UDP
# (-p 30000-30019:30000-30019 -p 30000-30019:30000-30019/udp).
EXPOSE 80 443 2222
ENTRYPOINT ["intergate"]
CMD ["start"]
