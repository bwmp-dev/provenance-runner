# syntax=docker/dockerfile:1
FROM golang:1.26.8-bookworm@sha256:a688600ca24f8a4d3ca77f95b0dd40704a9fc787c826660eb7ba0b641b8b175d AS build
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
