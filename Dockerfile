FROM gcr.io/distroless/static:nonroot@sha256:aafe993665bf6200db38a02c11a9351e782a84b6a45e7f33b6695638c88e3931

COPY oidc-ext-authz /oidc-ext-authz

EXPOSE 4181
USER nonroot:nonroot
ENTRYPOINT ["/oidc-ext-authz"]
