FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /securegate ./cmd/securegate

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /securegate /securegate
VOLUME /data
EXPOSE 80 443 2222
ENTRYPOINT ["/securegate", "-config", "/etc/securegate/securegate.yaml"]
