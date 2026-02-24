FROM gcr.io/distroless/static:nonroot

COPY oidc-ext-authz /oidc-ext-authz

EXPOSE 4181
USER nonroot:nonroot
ENTRYPOINT ["/oidc-ext-authz"]
