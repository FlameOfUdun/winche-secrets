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
    /// Whether reading would use the app's own credentials (its role, its environment) rather than ones the project
    /// keeps itself (<see cref="SecretSourceContext.GetStoredAsync"/>). On a host serving several projects, that lets a
    /// project read whatever the host can: <see cref="SecretStore.SetReferenceAsync"/> refuses it unless allowed.
    /// </summary>
    Task<bool> UsesAppCredentialsAsync(SecretSourceContext context, CancellationToken ct);

    /// <summary>The value (the whole of it: a JSON field is picked by the store). Throws <see cref="SecretReferenceException"/> with the source's reason.</summary>
    Task<string> ReadAsync(SecretReference reference, SecretSourceContext context, CancellationToken ct);
}

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
