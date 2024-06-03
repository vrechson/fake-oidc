# fake-oidc

A simple, insecure OpenID Connect provider intended for use in local development and automated tests.

## Features
 
Everything is stored in-memory, therefore data will not be persisted between restarts.

The provider supports `authorization_code` grant and `refresh_token` grant.

The provider attaches limited claims to the ID token: `name`, `sub`, `email`.

The provider has one built-in client:

- client id: `dev-client`
- client secret: `secure-secret`

All redirect urls are accepted.

## Configuration

By default fake-oidc starts on port 7835.
This can be overriden by setting the environment variable `FAKE_OIDC_HTTP_PORT`.

Example: `FAKE_OIDC_HTTP_PORT=1234 fake-oidc`.

## Login

On the login page, any username can be entered and will be accepted.

For automated tests, the query parameter `username=MY_USERNAME_HERE` can be added to the login
route to bypass the login form and callback to the resource server immediately.

## Disclaimer

There are probably many issues with this implementation, but it seems to work okay for basic testing.

Please report any issues.

