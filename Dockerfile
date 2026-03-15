FROM gcr.io/distroless/static:nonroot@sha256:f512d819b8f109f2375e8b51d8cfd8aafe81034bc3e319740128b7d7f70d5036

COPY oidc-ext-authz /oidc-ext-authz

EXPOSE 4181
USER nonroot:nonroot
ENTRYPOINT ["/oidc-ext-authz"]
