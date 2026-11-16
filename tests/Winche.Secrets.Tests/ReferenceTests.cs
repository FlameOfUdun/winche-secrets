using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Time.Testing;
using Npgsql;
using Winche.Core;

namespace Winche.Secrets.Tests;

/// <summary>A source in memory: values by locator; reads with the app's credentials unless the project keeps a key ("secrets.source.fake").</summary>
public sealed class FakeSource : ISecretSource
{
    public static readonly Dictionary<string, string> Values = new();
    public static int Reads;
    public string Name => "fake";
    public string Title => "Fake Vault";
    public string LocatorHint => "a path starting with /";
    public string? Problem(string locator) => locator.StartsWith('/') ? null : $"'{locator}' isn't a path: start it with /.";
    public async Task<bool> UsesAppCredentialsAsync(SecretSourceContext context, CancellationToken ct) =>
        await context.GetStoredAsync(SecretStore.SourcePrefix + "fake", ct) is null;
    public Task<string> ReadAsync(SecretReference reference, SecretSourceContext context, CancellationToken ct)
    {
        Interlocked.Increment(ref Reads);
        return Values.TryGetValue(reference.Locator, out var v) ? Task.FromResult(v)
            : throw new SecretReferenceException("not-found", $"Fake Vault has nothing at {reference.Locator}.");
    }
}

[Collection("postgres")]
public class ReferenceTests(PostgresFixture pg)
{
    private const string Key = "a-master-key-that-is-long-enough-1234";

    private static async Task<(ServiceProvider Sp, SecretStore Store, FakeTimeProvider Time)> Start(string db)
    {
        var time = new FakeTimeProvider(DateTimeOffset.Parse("2026-11-16T12:00:00Z"));
        var services = new ServiceCollection().AddLogging().AddSingleton<TimeProvider>(time);
        services.AddWincheConfig(o => { o.ConnectionString = db; o.MasterKey = Key; });
        services.AddWincheSecretSource<FakeSource>().AddWincheSecrets(o => o.CacheFor = TimeSpan.FromMinutes(5));
        var sp = services.BuildServiceProvider();
        foreach (var h in sp.GetServices<IHostedService>()) await h.StartAsync(default);
        return (sp, sp.GetRequiredService<SecretStore>(), time);
    }

    [Fact]
    public void References_are_written_source_colon_locator_hash_key()
    {
        var r = SecretReference.Parse("aws-sm:arn:aws:secretsmanager:eu-west-2:1:secret:app/ses-AbCd#secretAccessKey");
        Assert.Equal(("aws-sm", "arn:aws:secretsmanager:eu-west-2:1:secret:app/ses-AbCd", "secretAccessKey"), (r.Source, r.Locator, r.Key));
        Assert.Equal("aws-ssm:/app/key", SecretReference.Parse(" AWS-SSM:/app/key ").ToString());
        Assert.Null(SecretReference.Parse("no-colon", out var p1)); Assert.NotNull(p1);
        Assert.Null(SecretReference.Parse("aws-sm:", out _));
        Assert.Null(SecretReference.Parse("aws-sm:x#", out _));
    }

    [Fact]
    public async Task A_reference_reads_through_its_source_picks_its_json_field_and_is_kept_for_a_while()
    {
        var (sp, secrets, time) = await Start(await pg.NewDatabaseAsync());
        await using var _ = sp;
        FakeSource.Values["/app/ses"] = """{"accessKeyId":"AKIA1","secretAccessKey":"s3cr3t","port":587}""";
        FakeSource.Values["/app/plain"] = "just-a-value";

        await secrets.SetReferenceAsync("functions.secret.SES_SECRET", SecretReference.Parse("fake:/app/ses#secretAccessKey"), "admin@x", allowAppCredentials: true);
        await secrets.SetReferenceAsync("functions.secret.PLAIN", SecretReference.Parse("fake:/app/plain"), "admin@x", allowAppCredentials: true);
        await secrets.SetReferenceAsync("functions.secret.PORT", SecretReference.Parse("fake:/app/ses#port"), "admin@x", allowAppCredentials: true);
        await secrets.SetAsync("functions.secret.STORED", "kept-here", "admin@x");

        Assert.Equal("s3cr3t", await secrets.GetAsync("functions.secret.SES_SECRET"));
        Assert.Equal("just-a-value", await secrets.GetAsync("functions.secret.PLAIN"));
        Assert.Equal("587", await secrets.GetAsync("functions.secret.PORT"));
        Assert.Equal("kept-here", await secrets.GetAsync("functions.secret.STORED"));

        var list = await secrets.ListAsync("functions.secret.");
        Assert.Equal("fake:/app/ses#secretAccessKey", list.Single(i => i.Name.EndsWith("SES_SECRET")).Reference?.ToString());
        Assert.True(list.Single(i => i.Name.EndsWith("SES_SECRET")).ViaAppCredentials);
        Assert.Null(list.Single(i => i.Name.EndsWith("STORED")).Reference);

        // Rotated at the source: the old value until the cache runs out, then the new one.
        FakeSource.Values["/app/plain"] = "rotated";
        var reads = FakeSource.Reads;
        Assert.Equal("just-a-value", await secrets.GetAsync("functions.secret.PLAIN"));
        Assert.Equal(reads, FakeSource.Reads);
        time.Advance(TimeSpan.FromMinutes(6));
        Assert.Equal("rotated", await secrets.GetAsync("functions.secret.PLAIN"));

        // Nothing of the value is in the table; a value replaces a reference and back.
        await using (var conn = new NpgsqlConnection(sp.GetRequiredService<WincheConfigOptions>().ConnectionString))
        {
            await conn.OpenAsync();
            await using var raw = new NpgsqlCommand("SELECT count(*) FROM winche_secrets WHERE reference IS NOT NULL AND ciphertext IS NULL", conn);
            Assert.Equal(3L, await raw.ExecuteScalarAsync());
        }
        await secrets.SetAsync("functions.secret.PLAIN", "a value now", null);
        Assert.Null((await secrets.InfoAsync("functions.secret.PLAIN"))!.Reference);
        Assert.Equal("a value now", await secrets.GetAsync("functions.secret.PLAIN"));
        await secrets.SetFromAsync("functions.secret.PLAIN", null, "fake:/app/plain", null, allowAppCredentials: true);
        Assert.Equal("rotated", await secrets.GetAsync("functions.secret.PLAIN"));
        await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetFromAsync("functions.secret.PLAIN", "v", "fake:/x", null, true));

        // Master key changes don't touch references.
        Assert.Equal(new SecretKeyStatus(0, 1, 0), await secrets.ReencryptAsync());
    }

    [Fact]
    public async Task What_cant_be_read_says_why_and_tests_never_show_the_value()
    {
        var (sp, secrets, _) = await Start(await pg.NewDatabaseAsync());
        await using var _ = sp;
        FakeSource.Values["/t/json"] = """{"a":"1"}""";
        FakeSource.Values["/t/text"] = "not json";

        var unknown = await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetReferenceAsync("x.a", SecretReference.Parse("vault:/a"), null, true));
        Assert.Contains("use fake", unknown.Message);
        var bad = await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetReferenceAsync("x.a", SecretReference.Parse("fake:a"), null, true));
        Assert.Equal("invalid-argument", bad.Code);
        await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetReferenceAsync(SecretStore.SourcePrefix + "fake", SecretReference.Parse("fake:/a"), null, true));

        await secrets.SetReferenceAsync("x.missing", SecretReference.Parse("fake:/nothing"), null, true);
        var missing = await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.GetAsync("x.missing"));
        Assert.Contains("nothing at /nothing", missing.Message);
        await secrets.SetReferenceAsync("x.nofield", SecretReference.Parse("fake:/t/json#b"), null, true);
        Assert.Contains("doesn't have", (await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.GetAsync("x.nofield"))).Message);
        await secrets.SetReferenceAsync("x.notjson", SecretReference.Parse("fake:/t/text#a"), null, true);
        Assert.Contains("isn't JSON", (await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.GetAsync("x.notjson"))).Message);

        Assert.Equal(new SecretTestResult(true, null), await secrets.TestAsync(SecretReference.Parse("fake:/t/json#a"), true));
        Assert.False((await secrets.TestAsync(SecretReference.Parse("fake:/nothing"), true)).Ok);
        Assert.Equal("not-found", (await secrets.TestAsync("x.never")).Code);
        Assert.False((await secrets.TestAsync("x.missing")).Ok);
    }

    [Fact]
    public async Task The_apps_own_credentials_are_used_only_where_allowed_and_only_while_the_projects_key_is_absent()
    {
        var (sp, secrets, _) = await Start(await pg.NewDatabaseAsync());
        await using var _ = sp;
        FakeSource.Values["/p/one"] = "one";

        // No key of the project's own: reading would use the app's; refused unless allowed.
        var refused = await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetReferenceAsync("p.one", SecretReference.Parse("fake:/p/one"), "member@x", allowAppCredentials: false));
        Assert.Equal("permission-denied", refused.Code);
        Assert.Equal("permission-denied", (await secrets.TestAsync(SecretReference.Parse("fake:/p/one"), false)).Code);

        // With the project's own key: anyone who may set secrets may.
        await secrets.SetAsync(SecretStore.SourcePrefix + "fake", "project-key", "admin@x");
        await secrets.SetReferenceAsync("p.one", SecretReference.Parse("fake:/p/one"), "member@x", allowAppCredentials: false);
        Assert.False((await secrets.InfoAsync("p.one"))!.ViaAppCredentials);
        Assert.Equal("one", await secrets.GetAsync("p.one"));

        // The key removed later: it isn't read with the app's credentials instead.
        await secrets.DeleteAsync(SecretStore.SourcePrefix + "fake");
        await secrets.SetReferenceAsync("p.two", SecretReference.Parse("fake:/p/one"), "admin@server", allowAppCredentials: true);
        var e = await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.GetAsync("p.one"));
        Assert.Equal("permission-denied", e.Code);
        Assert.Equal("one", await secrets.GetAsync("p.two"));
    }
}

public class SourceKeyTests
{
    [Fact]
    public void A_source_key_is_checked_and_kept_as_json_of_its_fields()
    {
        var key = new SourceKey("secrets.source.x", "X key", [new("id", "Key ID"), new("secret", "Secret", Secret: true), new("region", "Region", Required: false)]);
        Assert.Equal("X key needs Secret.", key.Problem(new Dictionary<string, string?> { ["id"] = "a" }));
        Assert.Equal("X key has no field 'other'.", key.Problem(new Dictionary<string, string?> { ["id"] = "a", ["secret"] = "b", ["other"] = "c" }));
        Assert.Null(key.Problem(new Dictionary<string, string?> { ["id"] = "a", ["secret"] = "b", ["region"] = "" }));
        Assert.Equal("""{"id":"a","secret":"b"}""", key.ToJson(new Dictionary<string, string?> { ["id"] = " a ", ["secret"] = "b", ["region"] = "" }));
    }
}
