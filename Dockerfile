# syntax=docker/dockerfile:1
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/guard ./cmd/guard

FROM gcr.io/distroless/static-debian13:nonroot
COPY --from=build /out/guard /usr/local/bin/guard
USER 65532:65532
ENV LISTEN_ADDR=0.0.0.0:4444 FORWARDAUTH_LISTEN_ADDR=0.0.0.0:4445
EXPOSE 4444 4445
ENTRYPOINT ["/usr/local/bin/guard"]
