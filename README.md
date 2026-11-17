# Winche.Secrets

The secrets of a Winche app or server: passwords, API keys and client secrets (a Keycloak sync's, an SMTP server's, a
storage bucket's, functions' own). Each is either:

- a **value**, encrypted with the master key (AES-256-GCM, bound to its name) in the project's PostgreSQL database
  (`winche_secrets`), beside Winche.Core's settings; or
- a **reference** to where it really lives, e.g. AWS Secrets Manager or Parameter Store, read when it's needed and kept
  for a few minutes (so a rotation there is picked up).

Code reads either the same way: `await secrets.GetAsync("smtp.password")`. The console sets, replaces and removes
secrets; it never reads them back.

## Install

```sh
dotnet add package Winche.Secrets
dotnet add package Winche.Secrets.Aws   # references to AWS Secrets Manager and Parameter Store
```

Winche.Auth, Winche.Storage, Winche.Webhooks, Winche.Assets and Winche.Functions depend on Winche.Secrets and add the
store themselves, so an app using them already has it: add it yourself to keep secrets of your own, or for the AWS
sources. It keeps secrets where Winche.Core keeps settings (`AddWincheConfig`, with a master key).

## Use

```csharp
builder.Services.AddWincheConfig(o => { o.ConnectionString = conn; o.MasterKey = config["Winche:MasterKey"]; });
builder.Services.AddWincheSecrets(o => o.CacheFor = TimeSpan.FromMinutes(5));   // packages that keep secrets add it themselves too
builder.Services.AddWincheSecretsAws();                                          // Winche.Secrets.Aws: aws-sm and aws-ssm references
```

## References

Written `source:locator[#field]`:

| | |
| --- | --- |
| `aws-sm:arn:aws:secretsmanager:eu-west-2:123456789012:secret:app/ses-AbCdEf#secretAccessKey` | a field of a JSON secret in AWS Secrets Manager (the ARN gives the region) |
| `aws-sm:app/ses` | the whole secret, by name (the region from the project's key or the app's default) |
| `aws-ssm:/app/keycloak/clientSecret` | a Parameter Store parameter (SecureStrings decrypted) |

```csharp
await secrets.SetReferenceAsync("functions.secret.SES_SECRET", SecretReference.Parse("aws-sm:app/ses#secretAccessKey"), by, allowAppCredentials: true);
var check = await secrets.TestAsync("functions.secret.SES_SECRET");   // { Ok, Problem }: never the value
```

**Credentials.** A source reads with the project's own key when it keeps one (AWS: the secret `secrets.source.aws`,
`{"accessKeyId", "secretAccessKey", "region"?}`), else with the app's own credentials (its role, environment or
profile). On a host serving several projects the app's credentials could read anything granted to the host, so
`SetReferenceAsync` refuses them unless `allowAppCredentials` (Winche Server: server admins only). A reference set with
the project's key is never read with the app's credentials later, even if the key is removed.

Other sources implement `ISecretSource` and register with `services.AddWincheSecretSource<T>()`.

## Changing the master key

Deploy the new one as `MasterKey` and the old one in `PreviousMasterKeys`; on start every value still under the old
key is re-encrypted with the new one. References have nothing to re-encrypt.

## License

Elastic License 2.0
