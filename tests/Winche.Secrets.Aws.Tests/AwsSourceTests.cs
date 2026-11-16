using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Npgsql;
using Testcontainers.LocalStack;
using Testcontainers.PostgreSql;
using Winche.Core;

namespace Winche.Secrets.Aws.Tests;

public sealed class AwsFixture : IAsyncLifetime
{
    public PostgreSqlContainer Postgres { get; } = new PostgreSqlBuilder("postgres:17-alpine").Build();
    public LocalStackContainer LocalStack { get; } = new LocalStackBuilder("localstack/localstack:4").Build();
    public async Task InitializeAsync() => await Task.WhenAll(Postgres.StartAsync(), LocalStack.StartAsync());
    public async Task DisposeAsync() { await Postgres.DisposeAsync(); await LocalStack.DisposeAsync(); }

    public async Task<string> NewDatabaseAsync()
    {
        var name = $"a{Guid.NewGuid():N}"[..20];
        await using var conn = new NpgsqlConnection(Postgres.GetConnectionString());
        await conn.OpenAsync();
        await using var cmd = new NpgsqlCommand($"CREATE DATABASE {name}", conn);
        await cmd.ExecuteNonQueryAsync();
        return new NpgsqlConnectionStringBuilder(Postgres.GetConnectionString()) { Database = name }.ConnectionString;
    }
}

public class AwsSourceTests(AwsFixture aws) : IClassFixture<AwsFixture>
{
    private const string Region = "eu-west-2";
    private static readonly BasicAWSCredentials AppCredentials = new("test", "test");

    private async Task<SecretStore> Start()
    {
        var db = await aws.NewDatabaseAsync();
        var services = new ServiceCollection().AddLogging();
        services.AddWincheConfig(o => { o.ConnectionString = db; o.MasterKey = "a-master-key-that-is-long-enough-1234"; });
        services.AddWincheSecretsAws(o => { o.ServiceUrl = aws.LocalStack.GetConnectionString(); o.AppCredentials = AppCredentials; o.DefaultRegion = Region; });
        var sp = services.BuildServiceProvider();
        foreach (var h in sp.GetServices<IHostedService>()) await h.StartAsync(default);
        return sp.GetRequiredService<SecretStore>();
    }

    private AmazonSecretsManagerClient Sm() => new(AppCredentials, new AmazonSecretsManagerConfig { ServiceURL = aws.LocalStack.GetConnectionString(), AuthenticationRegion = Region });
    private AmazonSimpleSystemsManagementClient Ssm() => new(AppCredentials, new AmazonSimpleSystemsManagementConfig { ServiceURL = aws.LocalStack.GetConnectionString(), AuthenticationRegion = Region });

    [Fact]
    public async Task Secrets_manager_and_parameter_store_values_are_read_by_reference()
    {
        var secrets = await Start();
        var created = await Sm().CreateSecretAsync(new CreateSecretRequest { Name = "app/ses", SecretString = """{"accessKeyId":"AKIA1","secretAccessKey":"ses-secret"}""" });
        await Ssm().PutParameterAsync(new PutParameterRequest { Name = "/app/keycloak/clientSecret", Value = "kc-secret", Type = ParameterType.SecureString });
        await Ssm().PutParameterAsync(new PutParameterRequest { Name = "/app/plain", Value = "plain-value", Type = ParameterType.String });

        Assert.Equal(["aws-sm", "aws-ssm"], secrets.Sources.Select(s => s.Name).Order());
        await secrets.SetReferenceAsync("functions.secret.SES", SecretReference.Parse($"aws-sm:{created.ARN}#secretAccessKey"), "admin@x", allowAppCredentials: true);
        await secrets.SetReferenceAsync("functions.secret.SES_BY_NAME", SecretReference.Parse("aws-sm:app/ses#accessKeyId"), "admin@x", allowAppCredentials: true);
        await secrets.SetReferenceAsync("functions.secret.KC", SecretReference.Parse("aws-ssm:/app/keycloak/clientSecret"), "admin@x", allowAppCredentials: true);
        await secrets.SetReferenceAsync("functions.secret.PLAIN", SecretReference.Parse("aws-ssm:/app/plain"), "admin@x", allowAppCredentials: true);

        Assert.Equal("ses-secret", await secrets.GetAsync("functions.secret.SES"));
        Assert.Equal("AKIA1", await secrets.GetAsync("functions.secret.SES_BY_NAME"));
        Assert.Equal("kc-secret", await secrets.GetAsync("functions.secret.KC"));
        Assert.Equal("plain-value", await secrets.GetAsync("functions.secret.PLAIN"));

        // Missing ones say so; malformed ARNs are refused when set.
        var missing = await secrets.TestAsync(SecretReference.Parse("aws-ssm:/app/nothing"), true);
        Assert.Equal(("not-found", false), (missing.Code, missing.Ok));
        Assert.Contains("AWS Parameter Store has nothing at /app/nothing", missing.Problem);
        Assert.Equal("not-found", (await secrets.TestAsync(SecretReference.Parse("aws-sm:app/none"), true)).Code);
        await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetReferenceAsync("x", SecretReference.Parse("aws-sm:arn:aws:s3:::bucket"), null, true));
        await Assert.ThrowsAsync<SecretReferenceException>(() => secrets.SetReferenceAsync("x", SecretReference.Parse("aws-ssm:/with space"), null, true));
    }

    [Fact]
    public async Task Without_its_own_key_a_project_may_not_read_with_the_apps_credentials_unless_allowed()
    {
        var secrets = await Start();
        await Ssm().PutParameterAsync(new PutParameterRequest { Name = "/p/one", Value = "one", Type = ParameterType.SecureString });

        Assert.Equal("permission-denied", (await Assert.ThrowsAsync<SecretReferenceException>(() =>
            secrets.SetReferenceAsync("p.one", SecretReference.Parse("aws-ssm:/p/one"), "member@x", allowAppCredentials: false))).Code);

        // The project's own key (LocalStack takes any).
        await secrets.SetAsync(AwsProjectKey.SecretName, new AwsProjectKey("AKIAPROJECT", "project-secret", Region).ToJson(), "admin@x");
        await secrets.SetReferenceAsync("p.one", SecretReference.Parse("aws-ssm:/p/one"), "member@x", allowAppCredentials: false);
        Assert.Equal("one", await secrets.GetAsync("p.one"));

        // A key that isn't one says so.
        await secrets.SetAsync(AwsProjectKey.SecretName, "not json", "admin@x");
        Assert.Contains("accessKeyId", (await secrets.TestAsync("p.one")).Problem);
    }
}
