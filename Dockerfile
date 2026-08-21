FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7

COPY oidc-ext-authz /oidc-ext-authz

EXPOSE 4181
USER nonroot:nonroot
ENTRYPOINT ["/oidc-ext-authz"]
