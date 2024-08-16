FROM docker.io/library/alpine:3.20 as runtime

RUN \
  apk add --update --no-cache \
    bash \
    curl \
    ca-certificates \
    tzdata

ENTRYPOINT ["lieutenant-keycloak-idp-controller"]
COPY lieutenant-keycloak-idp-controller /usr/bin/

USER 65536:0
