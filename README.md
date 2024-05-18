# fake-oidc

This is a simple, insecure OpenID Connect provider intended for use in local development and
automated tests.

## Features
 
Everything is stored in-memory, therefore data will not be persisted between restarts.

The provider supports `authorization_code` grant and `refresh_token` grant.

The provider attaches limited claims to the ID token: `name`, `sub`, `email`.

The provider has one built-in client:

- client id: `dev-client`
- client secret: `secure-secret`

## Disclaimer

There are probably many issues with this implementation, but it seems to work okay for basic needs.

