FROM alpine:3.20
RUN apk add --no-cache curl ca-certificates \
 && update-ca-certificates
WORKDIR /app
# The stack mounts /port-sync.sh at runtime; no copy needed.
ENTRYPOINT ["/bin/sh","-c","/port-sync.sh"]
