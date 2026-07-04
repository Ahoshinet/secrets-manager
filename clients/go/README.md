# Secrets Manager Go Client

Native Go client for the Secrets Manager HTTP API.

```go
client, err := secrets.New(secrets.Config{
	ServerURL: "https://secrets.example.com",
	Token:     token,
})
if err != nil {
	return err
}

values, err := client.GetSecrets(ctx, "cdn")
if err != nil {
	return err
}
databaseURL := values["DATABASE_URL"]
defer databaseURL.Zeroize()

err = client.SetSecret(ctx, "cdn", "DATABASE_URL", secrets.Secret("postgres://new"))
```

Security defaults:

- `ServerURL` must use `https://`.
- Bearer tokens are sent only in the `Authorization` header.
- Secret values are exposed as mutable `Secret` byte slices so callers can
  zeroize them after use.
- Errors and string formatting do not include token or secret values.
