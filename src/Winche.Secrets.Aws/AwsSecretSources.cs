using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using Amazon;
using Amazon.Runtime;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Amazon.SimpleSystemsManagement;
using Amazon.SimpleSystemsManagement.Model;
using Microsoft.Extensions.DependencyInjection;

namespace Winche.Secrets.Aws;

/// <summary>How the AWS sources reach AWS.</summary>
public sealed class WincheSecretsAwsOptions
{
    /// <summary>The region for references without one (a name rather than an ARN), when the project's key doesn't say. Else the SDK's default (AWS_REGION, the profile).</summary>
    public string? DefaultRegion { get; set; }

    /// <summary>The app's own credentials. Null: the SDK's default chain (the instance or task role, the environment, the profile).</summary>
    public AWSCredentials? AppCredentials { get; set; }

    /// <summary>Another endpoint for both services (LocalStack, a VPC endpoint). Null: AWS's.</summary>
    public string? ServiceUrl { get; set; }
}

/// <summary>A project's own AWS key, kept as the secret <c>secrets.source.aws</c>: <c>{"accessKeyId", "secretAccessKey", "region"?}</c>.</summary>
public sealed record AwsProjectKey(string AccessKeyId, string SecretAccessKey, string? Region = null)
{
    /// <summary>The secret it's kept under.</summary>
    public const string SecretName = SecretStore.SourcePrefix + "aws";

    /// <summary>What the console asks for.</summary>
    public static readonly SourceKey Form = new(SecretName, "AWS access key",
    [
        new("accessKeyId", "Access key ID"),
        new("secretAccessKey", "Secret access key", Secret: true),
        new("region", "Region", Required: false, Hint: "for secrets named without an ARN, e.g. eu-west-2"),
    ]);

    public string ToJson() => JsonSerializer.Serialize(new Dictionary<string, string?> { ["accessKeyId"] = AccessKeyId, ["secretAccessKey"] = SecretAccessKey, ["region"] = Region });

    /// <summary>Reads the stored JSON; null (and why) when it isn't a key.</summary>
    public static AwsProjectKey? Parse(string? json, out string? problem)
    {
        problem = null;
        try
        {
            var o = JsonDocument.Parse(json ?? "").RootElement;
            string? Get(string n) => o.ValueKind == JsonValueKind.Object && o.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;
            if (Get("accessKeyId") is { Length: > 0 } id && Get("secretAccessKey") is { Length: > 0 } secret)
                return new AwsProjectKey(id.Trim(), secret.Trim(), Get("region") is { Length: > 0 } r ? r.Trim() : null);
        }
        catch (JsonException) { }
        problem = "The project's AWS key is {\"accessKeyId\": …, \"secretAccessKey\": …, \"region\": …(optional)}.";
        return null;
    }
}

/// <summary>What both AWS sources share: credentials (the project's key, else the app's), regions, clients.</summary>
public sealed class AwsSecretsAccess(WincheSecretsAwsOptions options)
{
    private readonly ConcurrentDictionary<string, IAmazonSecretsManager> _sm = new();
    private readonly ConcurrentDictionary<string, IAmazonSimpleSystemsManagement> _ssm = new();

    internal async Task<AwsProjectKey?> ProjectKeyAsync(SecretSourceContext context, CancellationToken ct) =>
        await context.GetStoredAsync(AwsProjectKey.SecretName, ct) is { } json
            ? AwsProjectKey.Parse(json, out var problem) ?? throw new SecretReferenceException("failed-precondition", problem!)
            : null;

    private (AWSCredentials? Credentials, string? Region, string CacheKey) Use(AwsProjectKey? key, string? region)
    {
        region ??= key?.Region ?? options.DefaultRegion ?? FallbackRegionFactory.GetRegionEndpoint()?.SystemName;
        if (string.IsNullOrEmpty(region) && options.ServiceUrl is null)
            throw new SecretReferenceException("failed-precondition", "No AWS region: use the secret's ARN, give the project's AWS key a region, or set the app's default region.");
        return key is null
            ? (options.AppCredentials, region, $"app|{region}")
            : (new BasicAWSCredentials(key.AccessKeyId, key.SecretAccessKey), region, $"{key.AccessKeyId}|{key.SecretAccessKey.GetHashCode()}|{region}");
    }

    private T Config<T>(T config, string? region) where T : ClientConfig
    {
        if (options.ServiceUrl is not null) { config.ServiceURL = options.ServiceUrl; config.AuthenticationRegion = region ?? "us-east-1"; }
        else config.RegionEndpoint = RegionEndpoint.GetBySystemName(region);
        return config;
    }

    internal IAmazonSecretsManager SecretsManager(AwsProjectKey? key, string? region)
    {
        var (credentials, r, k) = Use(key, region);
        return _sm.GetOrAdd(k, _ => credentials is null
            ? new AmazonSecretsManagerClient(Config(new AmazonSecretsManagerConfig(), r))
            : new AmazonSecretsManagerClient(credentials, Config(new AmazonSecretsManagerConfig(), r)));
    }

    internal IAmazonSimpleSystemsManagement ParameterStore(AwsProjectKey? key, string? region)
    {
        var (credentials, r, k) = Use(key, region);
        return _ssm.GetOrAdd(k, _ => credentials is null
            ? new AmazonSimpleSystemsManagementClient(Config(new AmazonSimpleSystemsManagementConfig(), r))
            : new AmazonSimpleSystemsManagementClient(credentials, Config(new AmazonSimpleSystemsManagementConfig(), r)));
    }

    /// <summary>AWS's refusal as a reference error the console can show.</summary>
    internal static SecretReferenceException Explain(AmazonServiceException e, string title, string locator) => e switch
    {
        _ when e.ErrorCode is "ResourceNotFoundException" or "ParameterNotFound" || e.StatusCode == HttpStatusCode.NotFound =>
            new SecretReferenceException("not-found", $"{title} has nothing at {locator}.", e),
        _ when e.ErrorCode is "AccessDeniedException" or "AccessDenied" or "UnrecognizedClientException" or "InvalidSignatureException"
            or "ExpiredTokenException" || e.StatusCode is HttpStatusCode.Forbidden or HttpStatusCode.Unauthorized =>
            new SecretReferenceException("permission-denied", $"{title} refused to read {locator}: {e.Message}", e),
        _ => new SecretReferenceException("unavailable", $"{title} couldn't read {locator}: {e.Message}", e),
    };

    /// <summary>The region of an ARN (arn:aws:service:region:account:…), or null when <paramref name="locator"/> isn't one.</summary>
    internal static string? RegionOf(string locator, string service)
    {
        var parts = locator.Split(':');
        return parts.Length >= 6 && parts[0] == "arn" && parts[2] == service && parts[3].Length > 0 ? parts[3] : null;
    }
}

/// <summary><c>aws-sm:</c> a secret in AWS Secrets Manager, by ARN (its region) or name; its current version.</summary>
public sealed class AwsSecretsManagerSource(AwsSecretsAccess aws) : ISecretSource
{
    public string Name => "aws-sm";
    public string Title => "AWS Secrets Manager";
    public string LocatorHint => "a secret's ARN (arn:aws:secretsmanager:<region>:<account>:secret:<name>) or its name";
    public SourceKey Key => AwsProjectKey.Form;

    public string? Problem(string locator) => locator switch
    {
        _ when locator.Any(char.IsWhiteSpace) => $"'{locator}' isn't a secret's ARN or name: no spaces.",
        _ when locator.StartsWith("arn:", StringComparison.Ordinal) && AwsSecretsAccess.RegionOf(locator, "secretsmanager") is null =>
            $"'{locator}' isn't a Secrets Manager ARN (arn:aws:secretsmanager:<region>:<account>:secret:<name>).",
        _ => null,
    };

    public async Task<bool> UsesAppCredentialsAsync(SecretSourceContext context, CancellationToken ct) => await aws.ProjectKeyAsync(context, ct) is null;

    public async Task<string> ReadAsync(SecretReference reference, SecretSourceContext context, CancellationToken ct)
    {
        var client = aws.SecretsManager(await aws.ProjectKeyAsync(context, ct), AwsSecretsAccess.RegionOf(reference.Locator, "secretsmanager"));
        try
        {
            var got = await client.GetSecretValueAsync(new GetSecretValueRequest { SecretId = reference.Locator }, ct);
            return got.SecretString ?? throw new SecretReferenceException("failed-precondition", $"{Title}: {reference.Locator} holds binary data, not text.");
        }
        catch (AmazonServiceException e) { throw AwsSecretsAccess.Explain(e, Title, reference.Locator); }
    }
}

/// <summary><c>aws-ssm:</c> a parameter in AWS Systems Manager Parameter Store, by name or ARN; SecureStrings decrypted.</summary>
public sealed class AwsParameterStoreSource(AwsSecretsAccess aws) : ISecretSource
{
    public string Name => "aws-ssm";
    public string Title => "AWS Parameter Store";
    public string LocatorHint => "a parameter's name (/app/key) or ARN (arn:aws:ssm:<region>:<account>:parameter/app/key)";
    public SourceKey Key => AwsProjectKey.Form;

    public string? Problem(string locator) => locator switch
    {
        _ when locator.Any(char.IsWhiteSpace) => $"'{locator}' isn't a parameter's name or ARN: no spaces.",
        _ when locator.StartsWith("arn:", StringComparison.Ordinal) && AwsSecretsAccess.RegionOf(locator, "ssm") is null =>
            $"'{locator}' isn't a Parameter Store ARN (arn:aws:ssm:<region>:<account>:parameter/<name>).",
        _ => null,
    };

    public async Task<bool> UsesAppCredentialsAsync(SecretSourceContext context, CancellationToken ct) => await aws.ProjectKeyAsync(context, ct) is null;

    public async Task<string> ReadAsync(SecretReference reference, SecretSourceContext context, CancellationToken ct)
    {
        var client = aws.ParameterStore(await aws.ProjectKeyAsync(context, ct), AwsSecretsAccess.RegionOf(reference.Locator, "ssm"));
        try
        {
            var got = await client.GetParameterAsync(new GetParameterRequest { Name = reference.Locator, WithDecryption = true }, ct);
            return got.Parameter.Value;
        }
        catch (AmazonServiceException e) { throw AwsSecretsAccess.Explain(e, Title, reference.Locator); }
    }
}

public static class SecretsAwsServiceCollectionExtensions
{
    /// <summary>
    /// Lets secrets be references to AWS Secrets Manager (<c>aws-sm:&lt;ARN or name&gt;[#field]</c>) and Parameter Store
    /// (<c>aws-ssm:&lt;name or ARN&gt;[#field]</c>). Read with a project's own key when it keeps one
    /// (<see cref="AwsProjectKey"/>), else the app's credentials (only where setting the reference allowed it).
    /// </summary>
    public static IServiceCollection AddWincheSecretsAws(this IServiceCollection services, Action<WincheSecretsAwsOptions>? configure = null)
    {
        var options = new WincheSecretsAwsOptions();
        configure?.Invoke(options);
        services.AddSingleton(new AwsSecretsAccess(options));
        services.AddWincheSecretSource<AwsSecretsManagerSource>();
        services.AddWincheSecretSource<AwsParameterStoreSource>();
        return services;
    }
}
