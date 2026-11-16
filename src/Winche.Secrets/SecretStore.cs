using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Winche.Secrets;

/// <summary>When a secret was set, and by whom: all the console ever shows of it.</summary>
public sealed record SecretInfo(string Name, DateTimeOffset SetAt, string? SetBy);

/// <summary>Where the secrets stand after a master key change: re-encrypted now, already current, readable by no key.</summary>
public sealed record SecretKeyStatus(int Reencrypted, int Current, int Unreadable);

/// <summary>
/// Passwords and keys the console saves (a Keycloak client secret, storage keys, SMTP passwords), encrypted with the
/// project's master key (AES-256-GCM) in <c>winche_secrets</c>. They can be replaced or removed; only the server code
/// that needs one can read it back, never the console.
/// </summary>
public sealed class SecretStore
{
    private readonly NpgsqlDataSource _db;
    private readonly byte[]? _key;
    private readonly byte[][] _previous;

    internal SecretStore(NpgsqlDataSource db, string? masterKey, IReadOnlyList<string>? previousKeys = null)
    {
        _db = db;
        _key = masterKey is null ? null : KeyFrom(masterKey);
        _previous = [.. (previousKeys ?? []).Select(KeyFrom)];
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

    /// <summary>Whether a master key is set (without one, secrets can't be saved).</summary>
    public bool Available => _key is not null;

    public async Task SetAsync(string name, string value, string? by, CancellationToken ct = default)
    {
        var key = _key ?? throw new InvalidOperationException("Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core) (32+ characters, from configuration).");
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("A secret can't be empty.", nameof(value));
        await using var cmd = _db.CreateCommand("""
            INSERT INTO winche_secrets (name, ciphertext, set_at, set_by) VALUES (@name, @c, now(), @by)
            ON CONFLICT (name) DO UPDATE SET ciphertext = excluded.ciphertext, set_at = excluded.set_at, set_by = excluded.set_by
            """);
        cmd.Parameters.AddWithValue("name", name);
        cmd.Parameters.AddWithValue("c", Seal(key, name, value));
        cmd.Parameters.AddWithValue("by", (object?)by ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    /// <summary>The secret's value, for server code that uses it. Null when it isn't set.</summary>
    public async Task<string?> GetAsync(string name, CancellationToken ct = default)
    {
        await using var cmd = _db.CreateCommand("SELECT ciphertext FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        if (await cmd.ExecuteScalarAsync(ct) is not byte[] stored) return null;
        var key = _key ?? throw new InvalidOperationException("Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core).");
        if (Open(key, name, stored) is { } value) return value;
        foreach (var previous in _previous)
            if (Open(previous, name, stored) is { } old) return old;
        throw new InvalidOperationException($"The secret '{name}' can't be read with this master key: was the key changed? Set the old one as a previous master key.");
    }

    /// <summary>
    /// After a master key change: re-encrypts every secret still under a previous key with the current one (each row
    /// once, safe with several servers). Without previous keys, only counts.
    /// </summary>
    public async Task<SecretKeyStatus> ReencryptAsync(CancellationToken ct = default)
    {
        var key = _key ?? throw new InvalidOperationException("Secrets need a master key: set WincheConfigOptions.MasterKey (Winche.Core).");
        var rows = new List<(string Name, byte[] Stored)>();
        await using (var read = _db.CreateCommand("SELECT name, ciphertext FROM winche_secrets"))
        await using (var r = await read.ExecuteReaderAsync(ct))
            while (await r.ReadAsync(ct)) rows.Add((r.GetString(0), (byte[])r[1]));
        int moved = 0, current = 0, unreadable = 0;
        foreach (var (name, stored) in rows)
        {
            if (Open(key, name, stored) is not null) { current++; continue; }
            var value = _previous.Select(p => Open(p, name, stored)).FirstOrDefault(v => v is not null);
            if (value is null) { unreadable++; continue; }
            // Only if nobody changed it meanwhile (another server, or the console).
            await using var write = _db.CreateCommand("UPDATE winche_secrets SET ciphertext = @new WHERE name = @name AND ciphertext = @old");
            write.Parameters.AddWithValue("new", Seal(key, name, value));
            write.Parameters.AddWithValue("name", name);
            write.Parameters.AddWithValue("old", stored);
            if (await write.ExecuteNonQueryAsync(ct) > 0) moved++; else current++;
        }
        return new SecretKeyStatus(moved, current, unreadable);
    }

    /// <summary>The secrets whose names start with <paramref name="prefix"/> (when and by whom each was set, never values), by name.</summary>
    public async Task<IReadOnlyList<SecretInfo>> ListAsync(string prefix, CancellationToken ct = default)
    {
        await using var cmd = _db.CreateCommand("SELECT name, set_at, set_by FROM winche_secrets WHERE starts_with(name, @prefix) ORDER BY name COLLATE \"C\"");
        cmd.Parameters.AddWithValue("prefix", prefix);
        var list = new List<SecretInfo>();
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
            list.Add(new SecretInfo(reader.GetString(0), new DateTimeOffset(reader.GetDateTime(1), TimeSpan.Zero), reader.IsDBNull(2) ? null : reader.GetString(2)));
        return list;
    }

    public async Task<SecretInfo?> InfoAsync(string name, CancellationToken ct = default)
    {
        await using var cmd = _db.CreateCommand("SELECT set_at, set_by FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        await using var reader = await cmd.ExecuteReaderAsync(ct);
        return await reader.ReadAsync(ct)
            ? new SecretInfo(name, new DateTimeOffset(reader.GetDateTime(0), TimeSpan.Zero), reader.IsDBNull(1) ? null : reader.GetString(1))
            : null;
    }

    public async Task<bool> DeleteAsync(string name, CancellationToken ct = default)
    {
        await using var cmd = _db.CreateCommand("DELETE FROM winche_secrets WHERE name = @name");
        cmd.Parameters.AddWithValue("name", name);
        return await cmd.ExecuteNonQueryAsync(ct) > 0;
    }
}
