# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/gate2sky ./cmd/gate2sky \
 && mkdir -p /out/data && chmod 700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gate2sky /usr/local/bin/gate2sky
COPY --from=build --chown=65532:65532 /out/data /data
# The configuration and all state live in /data:
#   docker run -it --rm -v gate2sky:/data IMAGE config   (create the configuration)
#   docker run -d -v gate2sky:/data -p ... IMAGE         (run it)
ENV GATE2SKY_CONFIG=/data/gate2sky.yaml \
    GATE2SKY_DATA_DIR=/data
VOLUME /data
# Plus the range of tcp.ports, if set (e.g. -p 30000-30019:30000-30019).
EXPOSE 80 443 2222
ENTRYPOINT ["gate2sky"]
CMD ["start"]
