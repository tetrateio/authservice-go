# Run E2E to Auth0 IDP

## Prerequisites
- Auth0 account and application (TODO: add auth0 setup doc)

## Setup
Provide the prover Auth0 application details in the `variables.env` file.
It must follow the following format:
```bash
export OIDC_CLIENT_ID=<client_id>
export OIDC_CLIENT_SECRET=<client_secret>
export AUTH0_HOST=<domain>
```

## Run
```bash
make e2e-test
```
