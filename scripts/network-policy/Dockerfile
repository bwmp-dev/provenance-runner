# Disposable kernel/network acceptance only. Never a production runtime image.
FROM python:3.13.7-alpine@sha256:9ba6d8cbebf0fb6546ae71f2a1c14f6ffd2fdab83af7fa5669734ef30ad48844
RUN apk add --no-cache nftables iproute2 conntrack-tools
ENTRYPOINT ["python3", "-B"]
