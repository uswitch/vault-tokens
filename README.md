# Vault-tokens
Vault-tokens requests a token from vault on your behalf using a user's forwarded groups to determine the policy applied to the token.

## Environment Variables

* `VAULT_SERVER` Vault server address
* `VAULT_TOKEN` Token for the server to interact with Vault
* `VAULT_CAPATH` Path to the vault server CA
* `CONFIG_PATH` Path to csv config file with allowed groups
* `REDIRECT` If set to `true` will redirect responses to http://localhost:63974/authed

## Config File
You can optionally use a config file with a comma separated list of the groups you want to allow. e.g:
```
super-users,read-only,analysts
```

## Headers
The application expects to receive a header `X-FORWARDED-GROUPS` in the format `GroupA|GroupB|GroupC` as well as a header for user name `X-FORWARDED-USER`.

## Redirecting to localhost
By default the token will be just included in the response but if you want to instead redirect the reponse to localhost (e.g for use in a cli tool) you can see `REDIRECT` to `true` and it will redirect the reponse to http://localhost:63974/authed.
