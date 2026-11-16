namespace Winche.Secrets;

/// <summary>
/// Where a secret's value really lives: a source (<see cref="Source"/>, e.g. <c>aws-sm</c>), what to read there
/// (<see cref="Locator"/>: an ARN, a parameter name), and optionally one field of a JSON value (<see cref="Key"/>).
/// Written <c>source:locator[#key]</c>, e.g. <c>aws-sm:arn:aws:secretsmanager:eu-west-2:123:secret:app/ses#secretAccessKey</c>.
/// Not itself secret: the console and CLI show it.
/// </summary>
public sealed record SecretReference(string Source, string Locator, string? Key = null)
{
    public override string ToString() => Key is null ? $"{Source}:{Locator}" : $"{Source}:{Locator}#{Key}";

    /// <summary>Reads <c>source:locator[#key]</c>; null (and why) when it isn't one.</summary>
    public static SecretReference? Parse(string? text, out string? problem)
    {
        problem = null;
        text = text?.Trim();
        var colon = text?.IndexOf(':') ?? -1;
        if (string.IsNullOrEmpty(text) || colon < 1 || colon == text.Length - 1)
        {
            problem = $"'{text}' isn't a reference: write source:what-to-read[#json-key], e.g. aws-sm:<secret ARN> or aws-ssm:<parameter name>.";
            return null;
        }
        var source = text[..colon].ToLowerInvariant();
        var rest = text[(colon + 1)..];
        var hash = rest.LastIndexOf('#');
        var (locator, key) = hash < 0 ? (rest, null) : (rest[..hash], rest[(hash + 1)..]);
        if (locator.Length == 0 || key is { Length: 0 })
        {
            problem = $"'{text}' isn't a reference: nothing to read" + (key is { Length: 0 } ? " after #." : ".");
            return null;
        }
        return new SecretReference(source, locator, key);
    }

    public static SecretReference Parse(string text) =>
        Parse(text, out var problem) ?? throw new SecretReferenceException("invalid-argument", problem!);
}

/// <summary>A reference that can't be set or read, and why (<see cref="Code"/>: <c>invalid-argument</c>, <c>permission-denied</c>, <c>failed-precondition</c>, <c>unavailable</c>).</summary>
public sealed class SecretReferenceException(string code, string message, Exception? inner = null) : InvalidOperationException(message, inner)
{
    public string Code { get; } = code;
}

/// <summary>
/// A place secrets are read from (AWS Secrets Manager, Parameter Store, …), registered with
/// <see cref="SecretsServiceCollectionExtensions.AddWincheSecretSource{T}"/>.
/// </summary>
public interface ISecretSource
{
    /// <summary>The name references use (<c>aws-sm</c>).</summary>
    string Name { get; }

    /// <summary>What people call it (<c>AWS Secrets Manager</c>).</summary>
    string Title { get; }

    /// <summary>What a locator looks like, for forms and errors (<c>a secret's ARN</c>).</summary>
    string LocatorHint { get; }

    /// <summary>Why <paramref name="locator"/> can't be read here, or null.</summary>
    string? Problem(string locator);

    /// <summary>
    /// The project's own key for this source, when it can have one: kept as a value under
    /// <see cref="SourceKey.SecretName"/> (a JSON object of <see cref="SourceKey.Fields"/>). Sources may share one
    /// (Secrets Manager and Parameter Store: one AWS key). Null: always the app's credentials.
    /// </summary>
    SourceKey? Key => null;

    /// <summary>
    /// Whether reading would use the app's own credentials (its role, its environment) rather than ones the project
    /// keeps itself (<see cref="SecretSourceContext.GetStoredAsync"/>). On a host serving several projects, that lets a
    /// project read whatever the host can: <see cref="SecretStore.SetReferenceAsync"/> refuses it unless allowed.
    /// </summary>
    Task<bool> UsesAppCredentialsAsync(SecretSourceContext context, CancellationToken ct);

    /// <summary>The value (the whole of it: a JSON field is picked by the store). Throws <see cref="SecretReferenceException"/> with the source's reason.</summary>
    Task<string> ReadAsync(SecretReference reference, SecretSourceContext context, CancellationToken ct);
}

/// <summary>A key a project keeps for a source (its own AWS access key): what the console asks for.</summary>
/// <param name="SecretName">Where it's kept (<c>secrets.source.aws</c>), as a JSON object of the fields.</param>
public sealed record SourceKey(string SecretName, string Title, IReadOnlyList<SourceKeyField> Fields)
{
    /// <summary>Why <paramref name="values"/> isn't a key (a required field missing, an unknown one), or null.</summary>
    public string? Problem(IReadOnlyDictionary<string, string?> values)
    {
        if (values.Keys.FirstOrDefault(k => Fields.All(f => f.Name != k)) is { } unknown) return $"{Title} has no field '{unknown}'.";
        var missing = Fields.Where(f => f.Required && string.IsNullOrWhiteSpace(values.GetValueOrDefault(f.Name))).Select(f => f.Title).ToList();
        return missing.Count > 0 ? $"{Title} needs {string.Join(" and ", missing)}." : null;
    }

    /// <summary>The JSON kept for <paramref name="values"/> (blank optional fields left out).</summary>
    public string ToJson(IReadOnlyDictionary<string, string?> values) => System.Text.Json.JsonSerializer.Serialize(
        Fields.Where(f => !string.IsNullOrWhiteSpace(values.GetValueOrDefault(f.Name))).ToDictionary(f => f.Name, f => values[f.Name]!.Trim()));
}

/// <summary>One field of a <see cref="SourceKey"/>; <see cref="Secret"/> ones are typed like passwords.</summary>
public sealed record SourceKeyField(string Name, string Title, bool Secret = false, bool Required = true, string? Hint = null);

/// <summary>What a source may use while reading: the values the project keeps itself (its own access keys).</summary>
public sealed class SecretSourceContext(Func<string, CancellationToken, Task<string?>> stored)
{
    /// <summary>A stored value (never a reference), e.g. the project's own key for a source; null when not set.</summary>
    public Task<string?> GetStoredAsync(string name, CancellationToken ct) => stored(name, ct);
}

/// <summary>Options for <see cref="SecretStore"/>.</summary>
public sealed class WincheSecretsOptions
{
    /// <summary>How long a value read through a reference is kept before it's read again (default 5 minutes; zero: every time).</summary>
    public TimeSpan CacheFor { get; set; } = TimeSpan.FromMinutes(5);
}
