using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Winche.Secrets;

/// <summary>
/// What the console ever shows of a secret: when it was set and by whom, and where it's read from when it's a
/// reference (<see cref="Reference"/>; null for a value kept here). Never the value.
/// </summary>
public sealed record SecretInfo(string Name, DateTimeOffset SetAt, string? SetBy, SecretReference? Reference = null)
{
    /// <summary>A reference read with the app's own credentials (allowed when it was set).</summary>
    public bool ViaAppCredentials { get; init; }
}

/// <summary>Where the secrets stand after a master key change: re-encrypted now, already current, readable by no key.</summary>
public sealed record SecretKeyStatus(int Reencrypted, int Current, int Unreadable);

/// <summary>Whether a reference could be read just now, and if not why. Never the value.</summary>
public sealed record SecretTestResult(bool Ok, string? Problem, string? Code = null);

/// <summary>
/// Passwords and keys (a Keycloak client secret, storage keys, SMTP passwords, functions' secrets) in
/// <c>winche_secrets</c>. Each is either a <b>value</b>, encrypted with the master key (AES-256-GCM, bound to its
/// name), or a <b>reference</b> to where it really lives (<see cref="SecretReference"/>), read through a registered
/// <see cref="ISecretSource"/> when it's needed and kept for <see cref="WincheSecretsOptions.CacheFor"/>.
/// <see cref="GetAsync"/> returns the value either way; the console sets, replaces and removes, never reads back.
/// </summary>
public sealed class SecretStore
{
    /// <summary>Names a source's own credentials are kept under (<c>secrets.source.aws</c>): always values, never references.</summary>
    public const string SourcePrefix = "secrets.source.";

    private readonly NpgsqlDataSource? _db;
    private readonly byte[]? _key;
    private readonly byte[][] _previous;
    private readonly Dictionary<string, ISecretSource> _sources;
    private readonly WincheSecretsOptions _options;
    private readonly TimeProvider _time;
    private readonly ConcurrentDictionary<string, (string Value, DateTimeOffset Until)> _cache = new();

    internal SecretStore(NpgsqlDataSource? db, string? masterKey, IReadOnlyList<string>? previousKeys = null,
        IEnumerable<ISecretSource>? sources = null, WincheSecretsOptions? options = null, TimeProvider? time = null)
    {
        _db = db;
        _key = masterKey is null ? null : KeyFrom(masterKey);
        _previous = [.. (previousKeys ?? []).Select(KeyFrom)];
        _sources = (sources ?? []).GroupBy(s => s.Name).ToDictionary(g => g.Key, g => g.Last());
        _options = options ?? new WincheSecretsOptions();
        _time = time ?? TimeProvider.System;
    }

    private static byte[] KeyFrom(string masterKey) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, Encoding.UTF8.GetBytes(masterKey), 32, info: Encoding.UTF8.GetBytes("winche-secrets"));

    private static byte[] Seal(byte[] key, string name, string value)
    {
        using var aes = new AesGcm(key, 16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var plain = Encoding.UTF8.GetBytes(value);
        var cipher = new byte[plain.Length];
        var tag = new byte[16];
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(name));   // bound to its name: can't be swapped with another
        return [.. nonce, .. tag, .. cipher];
    }

    private static string? Open(byte[] key, string name, byte[] stored)
    {
        using var aes = new AesGcm(key, 16);
        var plain = new byte[stored.Length - 28];
        try { aes.Decrypt(stored.AsSpan(0, 12), stored.AsSpan(28), stored.AsSpan(12, 16), plain, Encoding.UTF8.GetBytes(name)); }
        catch (AuthenticationTagMismatchException) { return null; }
        return Encoding.UTF8.GetString(plain);
    }

    /// <summary>Whether secrets can be kept: Winche.Core's settings database and a master key (AddWincheConfig).</summary>
    public bool Available => _db is not null && _key is not null;

    /// <summary>The sources references can name, by name.</summary>
    public IReadOnlyCollection<ISecretSource> Sources => _sources.Values;

    private const string NoDatabase = "Secrets are kept where Winche.Core keeps settings: call AddWincheConfig (with a master key).";
    private NpgsqlDataSource Db => _db ?? throw new InvalidOperationException(NoDatabase);

    /// <summary>Keeps <paramref name="value"/> under <paramref name="name"/>, encrypted (replacing a reference there).</summary>
    public async Task SetAsync(string name, string value, string? by, CancellationToken ct = default)
    {
        var key = _key ?? throw new InvalidOperationException(_db is null ? NoDatabase : "Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core; 32+ characters, from configuration).");
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("A secret can't be empty.", nameof(value));
        await using var cmd = Db.CreateCommand("""
            INSERT INTO winche_secrets (name, ciphertext, reference, app_credentials, set_at, set_by) VALUES (@name, @c, NULL, false, now(), @by)
            ON CONFLICT (name) DO UPDATE SET ciphertext = excluded.ciphertext, reference = NULL, app_credentials = false,
              set_at = excluded.set_at, set_by = excluded.set_by
            """);
        cmd.Parameters.AddWithValue("name", name);
        cmd.Parameters.AddWithValue("c", Seal(key, name, value));
        cmd.Parameters.AddWithValue("by", (object?)by ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
        Forget(name);
    }

    /// <summary>
    /// Makes <paramref name="name"/> a reference (replacing a value there). Checked first: the source exists, the
    /// locator is one it reads, and, when reading would use the app's own credentials, that the caller may
    /// (<paramref name="allowAppCredentials"/>: on a host serving several projects, only its admins). The value
    /// isn't read: <see cref="TestAsync(SecretReference, bool, CancellationToken)"/> does that.
    /// </summary>
    public async Task SetReferenceAsync(string name, SecretReference reference, string? by, bool allowAppCredentials, CancellationToken ct = default)
    {
        if (!Available) throw new InvalidOperationException(_db is null ? NoDatabase : "Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core).");
        if (name.StartsWith(SourcePrefix, StringComparison.Ordinal))
            throw new SecretReferenceException("invalid-argument", "A source's own credentials are kept here as a value, not read from elsewhere.");
        var viaApp = await CheckAsync(reference, allowAppCredentials, ct);
        await using var cmd = Db.CreateCommand("""
            INSERT INTO winche_secrets (name, ciphertext, reference, app_credentials, set_at, set_by) VALUES (@name, NULL, @r, @app, now(), @by)
            ON CONFLICT (name) DO UPDATE SET ciphertext = NULL, reference = excluded.reference, app_credentials = excluded.app_credentials,
              set_at = excluded.set_at, set_by = excluded.set_by
            """);
        cmd.Parameters.AddWithValue("name", name);
        cmd.Parameters.AddWithValue("r", reference.ToString());
        cmd.Parameters.AddWithValue("app", viaApp);
        cmd.Parameters.AddWithValue("by", (object?)by ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
        Forget(name);
    }

    /// <summary>
    /// Sets <paramref name="name"/> from what a form or the CLI sent: a value, or a reference (exactly one of them).
    /// </summary>
    public Task SetFromAsync(string name, string? value, string? reference, string? by, bool allowAppCredentials, CancellationToken ct = default) =>
        (string.IsNullOrEmpty(value), string.IsNullOrWhiteSpace(reference)) switch
        {
            (false, true) => SetAsync(name, value!, by, ct),
            (true, false) => SetReferenceAsync(name, SecretReference.Parse(reference!), by, allowAppCredentials, ct),
            (false, false) => throw new SecretReferenceException("invalid-argument", "Send a value or a reference, not both."),
            _ => throw new SecretReferenceException("invalid-argument", "Send a value or a reference."),
        };

    /// <summary>The source a reference names, its locator checked, and whether it would read with the app's credentials (refused unless allowed).</summary>
    private async Task<bool> CheckAsync(SecretReference reference, bool allowAppCredentials, CancellationToken ct)
    {
        var source = SourceOf(reference);
        if (source.Problem(reference.Locator) is { } problem) throw new SecretReferenceException("invalid-argument", problem);
        var viaApp = await source.UsesAppCredentialsAsync(Context, ct);
        if (viaApp && !allowAppCredentials)
            throw new SecretReferenceException("permission-denied",
                $"Reading from {source.Title} with this server's own credentials is for its admins. Set the project's own {source.Title} key first, or ask a server admin.");
        return viaApp;
    }

    private ISecretSource SourceOf(SecretReference reference) => _sources.TryGetValue(reference.Source, out var s) ? s
        : throw new SecretReferenceException("invalid-argument", _sources.Count == 0
            ? $"Secrets can't be read from '{reference.Source}' here: this app reads from no other place (e.g. Winche.Secrets.Aws's AddWincheSecretsAws)."
            : $"Secrets can't be read from '{reference.Source}' here: use {string.Join(" or ", _sources.Keys.Order())}.");

    private SecretSourceContext Context => new(GetStoredAsync);

    /// <summary>A value kept here (a reference there reads as nothing): what sources use for their own credentials.</summary>
    private async Task<string?> GetStoredAsync(string name, CancellationToken ct)
    {
        if (_db is null) return null;
        await using var cmd = Db.CreateCommand("SELECT ciphertext FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        return await cmd.ExecuteScalarAsync(ct) is byte[] stored ? Decrypt(name, stored) : null;
    }

    private string Decrypt(string name, byte[] stored)
    {
        var key = _key ?? throw new InvalidOperationException("Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core).");
        if (Open(key, name, stored) is { } value) return value;
        foreach (var previous in _previous)
            if (Open(previous, name, stored) is { } old) return old;
        throw new InvalidOperationException($"The secret '{name}' can't be read with this master key: was the key changed? Set the old one as a previous master key.");
    }

    /// <summary>
    /// The secret's value, for server code that uses it: decrypted, or read through its reference (kept for
    /// <see cref="WincheSecretsOptions.CacheFor"/>). Null when it isn't set. A reference that can't be read throws
    /// <see cref="SecretReferenceException"/> with the source's reason.
    /// </summary>
    public async Task<string?> GetAsync(string name, CancellationToken ct = default)
    {
        if (_db is null) return null;
        await using var cmd = Db.CreateCommand("SELECT ciphertext, reference, app_credentials FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        byte[]? stored; string? reference; bool viaApp;
        await using (var r = await cmd.ExecuteReaderAsync(ct))
        {
            if (!await r.ReadAsync(ct)) return null;
            (stored, reference, viaApp) = (r.IsDBNull(0) ? null : (byte[])r[0], r.IsDBNull(1) ? null : r.GetString(1), r.GetBoolean(2));
        }
        if (stored is not null) return Decrypt(name, stored);
        var cacheKey = $"{name}\n{reference}";
        if (_cache.TryGetValue(cacheKey, out var hit) && hit.Until > _time.GetUtcNow()) return hit.Value;
        var value = await ReadAsync(SecretReference.Parse(reference!), viaApp, name, ct);
        if (_options.CacheFor > TimeSpan.Zero) _cache[cacheKey] = (value, _time.GetUtcNow() + _options.CacheFor);
        return value;
    }

    /// <summary>Reads through the source, the JSON field picked; the app's credentials only if that was allowed when it was set.</summary>
    private async Task<string> ReadAsync(SecretReference reference, bool allowAppCredentials, string? name, CancellationToken ct)
    {
        var source = SourceOf(reference);
        var label = name is null ? reference.ToString() : $"'{name}' ({reference})";
        if (!allowAppCredentials && await source.UsesAppCredentialsAsync(Context, ct))
            throw new SecretReferenceException("permission-denied",
                $"The secret {label} was set to be read with the project's own {source.Title} key, which is no longer set.");
        string raw;
        try { raw = await source.ReadAsync(reference, Context, ct); }
        catch (SecretReferenceException) { throw; }
        catch (Exception e) when (e is not OperationCanceledException)
        {
            throw new SecretReferenceException("unavailable", $"The secret {label} couldn't be read from {source.Title}: {e.Message}", e);
        }
        return reference.Key is null ? raw : Field(raw, reference.Key, label);
    }

    private static string Field(string raw, string key, string label)
    {
        JsonElement root;
        try { root = JsonDocument.Parse(raw).RootElement; }
        catch (JsonException) { throw new SecretReferenceException("failed-precondition", $"The secret {label} names the field '{key}', but its value isn't JSON."); }
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty(key, out var field))
            throw new SecretReferenceException("failed-precondition", $"The secret {label} names the field '{key}', which its value doesn't have.");
        return field.ValueKind == JsonValueKind.String ? field.GetString()! : field.GetRawText();
    }

    /// <summary>
    /// Reads <paramref name="reference"/> now (no cache), to say whether it works before or after it's set; with the
    /// app's credentials only if <paramref name="allowAppCredentials"/>. Never returns the value.
    /// </summary>
    public async Task<SecretTestResult> TestAsync(SecretReference reference, bool allowAppCredentials, CancellationToken ct = default)
    {
        try
        {
            await CheckAsync(reference, allowAppCredentials, ct);
            await ReadAsync(reference, allowAppCredentials, null, ct);
            return new SecretTestResult(true, null);
        }
        catch (SecretReferenceException e) { return new SecretTestResult(false, e.Message, e.Code); }
    }

    /// <summary>Reads the secret <paramref name="name"/> now (no cache): whether it works. Values kept here always do.</summary>
    public async Task<SecretTestResult> TestAsync(string name, CancellationToken ct = default)
    {
        var info = await InfoAsync(name, ct);
        if (info is null) return new SecretTestResult(false, $"The secret '{name}' isn't set.", "not-found");
        if (info.Reference is null) return new SecretTestResult(true, null);
        Forget(name);
        try { await GetAsync(name, ct); return new SecretTestResult(true, null); }
        catch (SecretReferenceException e) { return new SecretTestResult(false, e.Message, e.Code); }
    }

    /// <summary>Drops what's cached for <paramref name="name"/>; for a source's own credentials, everything (they decide what may be read).</summary>
    private void Forget(string name)
    {
        if (name.StartsWith(SourcePrefix, StringComparison.Ordinal)) { _cache.Clear(); return; }
        foreach (var k in _cache.Keys.Where(k => k.StartsWith(name + "\n", StringComparison.Ordinal))) _cache.TryRemove(k, out _);
    }

    /// <summary>
    /// After a master key change: re-encrypts every value still under a previous key with the current one (each row
    /// once, safe with several servers). References have nothing to re-encrypt. Without previous keys, only counts.
    /// </summary>
    public async Task<SecretKeyStatus> ReencryptAsync(CancellationToken ct = default)
    {
        var key = _key ?? throw new InvalidOperationException("Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core).");
        var rows = new List<(string Name, byte[] Stored)>();
        await using (var read = Db.CreateCommand("SELECT name, ciphertext FROM winche_secrets WHERE ciphertext IS NOT NULL"))
        await using (var r = await read.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) rows.Add((r.GetString(0), (byte[])r[1]));
        int moved = 0, current = 0, unreadable = 0;
        foreach (var (name, stored) in rows)
        {
            if (Open(key, name, stored) is not null) { current++; continue; }
            var value = _previous.Select(p => Open(p, name, stored)).FirstOrDefault(v => v is not null);
            if (value is null) { unreadable++; continue; }
            // Only if nobody changed it meanwhile (another server, or the console).
            await using var write = Db.CreateCommand("UPDATE winche_secrets SET ciphertext = @new WHERE name = @name AND ciphertext = @old");
            write.Parameters.AddWithValue("new", Seal(key, name, value));
            write.Parameters.AddWithValue("name", name);
            write.Parameters.AddWithValue("old", stored);
            if (await write.ExecuteNonQueryAsync(ct) > 0) moved++; else current++;
        }
        return new SecretKeyStatus(moved, current, unreadable);
    }

    private static SecretInfo InfoFrom(NpgsqlDataReader r, int at) => new(
        r.GetString(at), new DateTimeOffset(r.GetDateTime(at + 1), TimeSpan.Zero), r.IsDBNull(at + 2) ? null : r.GetString(at + 2),
        r.IsDBNull(at + 3) ? null : SecretReference.Parse(r.GetString(at + 3), out _)) { ViaAppCredentials = r.GetBoolean(at + 4) };

    /// <summary>The secrets whose names start with <paramref name="prefix"/> (when, by whom, where from; never values), by name.</summary>
    public async Task<IReadOnlyList<SecretInfo>> ListAsync(string prefix, CancellationToken ct = default)
    {
        if (_db is null) return [];
        await using var cmd = Db.CreateCommand("SELECT name, set_at, set_by, reference, app_credentials FROM winche_secrets WHERE starts_with(name, @prefix) ORDER BY name COLLATE \"C\"");
        cmd.Parameters.AddWithValue("prefix", prefix);
        var list = new List<SecretInfo>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct)) list.Add(InfoFrom(reader, 0));
        return list;
    }

    public async Task<SecretInfo?> InfoAsync(string name, CancellationToken ct = default)
    {
        if (_db is null) return null;
        await using var cmd = Db.CreateCommand("SELECT name, set_at, set_by, reference, app_credentials FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct) ? InfoFrom(reader, 0) : null;
    }

    public async Task<bool> DeleteAsync(string name, CancellationToken ct = default)
    {
        if (_db is null) return false;
        await using var cmd = Db.CreateCommand("DELETE FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        Forget(name);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }
}
