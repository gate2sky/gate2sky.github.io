# syntax=docker/dockerfile:1
FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/securegate ./cmd/securegate \
 && mkdir -p /out/data && chmod 700 /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/securegate /usr/local/bin/securegate
COPY --from=build --chown=65532:65532 /out/data /data
# The configuration and all state live in /data:
#   docker run -it --rm -v securegate:/data IMAGE config   (create the configuration)
#   docker run -d -v securegate:/data -p ... IMAGE         (run it)
ENV SECUREGATE_CONFIG=/data/securegate.yaml \
    SECUREGATE_DATA_DIR=/data
VOLUME /data
EXPOSE 80 443 2222
ENTRYPOINT ["securegate"]
CMD ["start"]
