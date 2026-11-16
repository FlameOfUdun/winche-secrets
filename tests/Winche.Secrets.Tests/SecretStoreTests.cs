using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Testcontainers.PostgreSql;
using Winche.Core;

namespace Winche.Secrets.Tests;

public sealed class PostgresFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _container = new PostgreSqlBuilder("postgres:17-alpine").Build();
    public async Task InitializeAsync() => await _container.StartAsync();
    public async Task DisposeAsync() => await _container.DisposeAsync();

    public async Task<string> NewDatabaseAsync()
    {
        var name = $"s{Guid.NewGuid():N}"[..20];
        await using var conn = new NpgsqlConnection(_container.GetConnectionString());
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {name}", conn);
        await cmd.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(_container.GetConnectionString()) { Database = name }.ConnectionString;
    }
}

[CollectionDefinition("postgres")]
public sealed class PostgresCollection : ICollectionFixture<PostgresFixture>;

[Collection("postgres")]
public class SecretStoreTests(PostgresFixture pg)
{
    private static async Task<ServiceProvider> Start(string db, string? masterKey, params string[] previous)
    {
        var services = new ServiceCollection().AddLogging();
        services.AddWincheConfig(o => { o.ConnectionString = db; o.MasterKey = masterKey; o.PreviousMasterKeys = previous; });
        services.AddWincheSecrets().AddWincheSecrets();   // twice is fine
        var sp = services.BuildServiceProvider();
        foreach (var h in sp.GetServices<IHostedService>()) await h.StartAsync(default);
        return sp;
    }

    [Fact]
    public async Task Without_the_settings_database_nothing_is_set_and_nothing_can_be_saved()
    {
        var sp = new ServiceCollection().AddLogging().AddWincheSecrets().BuildServiceProvider();
        foreach (var h in sp.GetServices<IHostedService>()) await h.StartAsync(default);
        var secrets = sp.GetRequiredService<SecretStore>();
        Assert.False(secrets.Available);
        Assert.Null(await secrets.GetAsync("smtp.password"));
        Assert.Empty(await secrets.ListAsync(""));
        var e = await Assert.ThrowsAsync<InvalidOperationException>(() => secrets.SetAsync("smtp.password", "x", null));
        Assert.Contains("AddWincheConfig", e.Message);
    }

    [Fact]
    public async Task A_changed_master_key_reads_secrets_with_the_previous_one_and_re_encrypts_them_on_start()
    {
        var db = await pg.NewDatabaseAsync();
        const string oldKey = "old-master-key-0123456789abcdefghijklmnop", newKey = "new-master-key-0123456789abcdefghijklmnop";
        await using (var before = await Start(db, oldKey))
        {
            await before.GetRequiredService<SecretStore>().SetAsync("smtp.password", "pw-1", "admin@x");
            await before.GetRequiredService<SecretStore>().SetAsync("keycloak.clientSecret", "pw-2", "admin@x");
        }

        // The new key alone can't read them.
        await using (var alone = await Start(db, newKey))
            await Assert.ThrowsAsync<InvalidOperationException>(() => alone.GetRequiredService<SecretStore>().GetAsync("smtp.password"));

        // With the old one as previous: re-encrypted on start, who set them kept.
        await using (var rotating = await Start(db, newKey, oldKey))
        {
            var secrets = rotating.GetRequiredService<SecretStore>();
            Assert.Equal(new SecretKeyStatus(0, 2, 0), await secrets.ReencryptAsync());
            Assert.Equal("admin@x", (await secrets.InfoAsync("smtp.password"))?.SetBy);
        }

        // Now the new key alone reads everything.
        await using var after = await Start(db, newKey);
        Assert.Equal("pw-1", await after.GetRequiredService<SecretStore>().GetAsync("smtp.password"));
        Assert.Equal("pw-2", await after.GetRequiredService<SecretStore>().GetAsync("keycloak.clientSecret"));
    }

    [Fact]
    public async Task Secrets_are_encrypted_bound_to_their_name_and_never_need_reading_back()
    {
        var db = await pg.NewDatabaseAsync();
        const string key = "a-master-key-that-is-long-enough-1234";
        await using (var sp = await Start(db, key))
        {
            var secrets = sp.GetRequiredService<SecretStore>();
            await secrets.SetAsync("keycloak.clientSecret", "s3cr3t-value", "admin@x");
            await secrets.SetAsync("smtp.password", "another", "admin@x");
            Assert.Equal("s3cr3t-value", await secrets.GetAsync("keycloak.clientSecret"));
            Assert.Equal("admin@x", (await secrets.InfoAsync("keycloak.clientSecret"))?.SetBy);
            await secrets.SetAsync("functions.secret.B", "b", null);
            await secrets.SetAsync("functions.secret.A", "a", "admin@x");
            Assert.Equal(["functions.secret.A", "functions.secret.B"], (await secrets.ListAsync("functions.secret.")).Select(i => i.Name));
            Assert.Empty(await secrets.ListAsync("nothing."));
            Assert.Null(await secrets.GetAsync("nope"));

            await using var conn = new NpgsqlConnection(db);
            await conn.OpenAsync();
            await using (var raw = new NpgsqlCommand("SELECT ciphertext FROM winche_secrets WHERE name = 'keycloak.clientSecret'", conn))
                Assert.DoesNotContain("s3cr3t", System.Text.Encoding.UTF8.GetString((byte[])(await raw.ExecuteScalarAsync())!));
            // Copying one secret's ciphertext onto another name doesn't make it readable there.
            await using (var swap = new NpgsqlCommand("UPDATE winche_secrets SET ciphertext = (SELECT ciphertext FROM winche_secrets WHERE name = 'keycloak.clientSecret') WHERE name = 'smtp.password'", conn))
                await swap.ExecuteNonQueryAsync();
            await Assert.ThrowsAsync<InvalidOperationException>(() => secrets.GetAsync("smtp.password"));
            Assert.True(await secrets.DeleteAsync("smtp.password"));
        }

        // Another key can't read them; no key can't save them.
        await using (var wrong = await Start(db, "a-different-master-key-also-long-enough"))
            await Assert.ThrowsAsync<InvalidOperationException>(() => wrong.GetRequiredService<SecretStore>().GetAsync("keycloak.clientSecret"));
        await using var none = await Start(db, null);
        Assert.False(none.GetRequiredService<SecretStore>().Available);
        await Assert.ThrowsAsync<InvalidOperationException>(() => none.GetRequiredService<SecretStore>().SetAsync("x", "y", null));
    }
}
