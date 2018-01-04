FROM scratch

ADD bin/vault-tokens vault-tokens

ENTRYPOINT ["/vault-tokens"]
