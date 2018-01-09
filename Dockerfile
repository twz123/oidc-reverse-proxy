# Use a real distro instead of scratch in order to have some precanned certificate authorities
FROM alpine:3.7
RUN apk add -U ca-certificates && rm -rf /var/cache/apk/*
ADD oidc-reverse-proxy /
ENTRYPOINT [ "/oidc-reverse-proxy" ]
