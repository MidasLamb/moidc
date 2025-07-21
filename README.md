# MOIDC
Mocked OpenID Connect (OIDC) server for testing purposes.

# Primary use case
When you're developing an application that uses OIDC for authentication, you might not want to rely on a real OIDC provider for testing.
MOIDC allows you to mock the OIDC flow, enabling you to test your application without needing a real OIDC server.
You won't have to provision any users, every user is logged in without requiring a password.

# WARNING
THIS IS NOT A REAL OIDC SERVER. IT IS INTENDED FOR TESTING PURPOSES ONLY.
SINCE THERE IS NOT 

# Features
* passwordless logins
* will redirect immediately if `login_hint` is provided

# Running
## Configuration
MOIDC can be configured using environment variables. The following variables are available:
- `MOIDC_BASE_URL`: The base URL where the OIDC server is reachable. I.e. if your proxying this, set this to the url of the proxy.
- `MOIDC_PORT`: The port on which the OIDC server should listen. Defaults to `3000`.

### As part of a docker compose setup
```yaml
services:
  moidc:
    image: ghcr.io/midaslamb/moidc:latest
    ports:
      - 3000:3000
    environment:
      - MOIDC_BASE_URL=http://localhost:3000/ # The url where the OIDC server is reachable
      - MOIDC_PORT=3000 # The port on which the OIDC server should listen
```

