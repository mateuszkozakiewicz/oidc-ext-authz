FROM gcr.io/distroless/static:nonroot@sha256:f7f8f729987ad0fdf6b05eeeae94b26e6a0f613bdf46feea7fc40f7bd72953e6

COPY oidc-ext-authz /oidc-ext-authz

EXPOSE 4181
USER nonroot:nonroot
ENTRYPOINT ["/oidc-ext-authz"]
