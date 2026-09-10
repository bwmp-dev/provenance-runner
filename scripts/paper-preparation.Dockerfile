# syntax=docker/dockerfile:1
FROM golang:1.25.13-bookworm@sha256:e401dae1bf814e29204a8cb7915682e1780951e609ca0dd8865ee1937f510c48 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/provenance-paper-runtime ./cmd/provenance-paper-runtime

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates libstdc++6 zlib1g && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/provenance-paper-runtime /usr/local/bin/provenance-paper-runtime
COPY scripts/prepare-paper-catalog.py /usr/local/lib/prepare-paper-catalog.py
USER 65532:65532
ENTRYPOINT ["python3", "-I", "/usr/local/lib/prepare-paper-catalog.py", "--catalog", "/work/catalog.json", "--java-archive", "/work/java.tar.gz", "--paper", "/work/paper.jar", "--runtime-tool", "/usr/local/bin/provenance-paper-runtime", "--runtime-uri", "https://preparation.invalid/runtime", "--output-dir", "/work/output", "--maximum-prepared-bytes", "1073741824"]
