# Winche.Secrets

The secrets of a Winche app or server: passwords, API keys and client secrets (a Keycloak sync's, an SMTP server's, a
storage bucket's, functions' own). Encrypted with the master key (AES-256-GCM, each bound to its name) in the
project's PostgreSQL database (`winche_secrets`), beside Winche.Core's settings. The console can set, replace and
remove them; only server code that needs one reads it back.

```csharp
builder.Services.AddWincheConfig(o => { o.ConnectionString = conn; o.MasterKey = config["Winche:MasterKey"]; });
builder.Services.AddWincheSecrets();   // packages that keep secrets add it themselves too
```

Changing the master key: deploy the new one as `MasterKey` and the old one in `PreviousMasterKeys`; on start every
secret still under the old key is re-encrypted with the new one.

## License

Elastic License 2.0
