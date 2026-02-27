# What is this

Stateless forward authentication service for self-hosted infrastructure.

Provides Google OIDC authentication and per-domain access control for self-hosted applications. Implements the HTTP forward auth protocol, making it compatible with Traefik, Envoy Gateway, Istio, and any other reverse proxy supporting external authorization.

Allows to provide selective access to self-hosted applications when maintaining own identity provider like Authentik is overkill.

## Features

- Google OIDC authentication — standard Gmail accounts, no Workspace required
- Per-subdomain email allowlists configured via a single YAML file
- Single signed session cookie scoped to the root domain — authenticate once, access all subdomains
- Single OAuth2 callback URL regardless of how many domains are protected
- Stateless — no database, no Redis, no external dependencies

## Configuration

All configuration lives in a single YAML file. See [examples/config.yaml](examples/config.yaml) for a full reference.

## Google OAuth Setup

1. Go to [GCP Console](https://console.cloud.google.com) -> APIs & Services -> Credentials
2. Create credentials -> OAuth client ID (Web application)
3. Add Authorized redirect URI: `https://auth.example.com/oauth2/callback`
4. Copy the Client ID and Client Secret to your config

## Traefik Integration

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: forward-auth
  namespace: default
spec:
  forwardAuth:
    address: http://forward-auth.default.svc.cluster.local:4181
    trustForwardHeader: true
    authResponseHeaders:
      - X-Forwarded-User
      - X-Auth-Request-Email
```

## Envoy Gateway Integration

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: forward-auth
spec:
  targetRefs:
  - group: gateway.networking.k8s.io
    kind: HTTPRoute
    name: your-route
  extAuth:
    http:
      backendRefs:
      - name: forward-auth
        namespace: default
        port: 4181
      path: "/"
      headersToExtAuth:
      - cookie
      - x-forwarded-host
      - x-forwarded-proto
      - x-forwarded-uri
```

## Endpoints

| Path (default) | Description |
| ---------------------- | ------------------------------------------------------------------------------------ |
| `GET /` | Forward auth endpoint |
| `GET /oauth2/callback` | Google OAuth2 callback |
| `GET /signout` | Clears session cookie and redirects to `server.defaultRedirectURL` or `?rd=` param |
| `GET /healthz` | Returns 200 |
| `GET /me` | Returns authenticated user claims |

## Environment Variables

| Variable      | Default               | Description                  |
| ------------- | --------------------- | ---------------------------- |
| `CONFIG_PATH` | `/config/config.yaml` | Path to the YAML config file |
