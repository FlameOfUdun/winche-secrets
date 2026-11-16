using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Npgsql;
using Winche.Core;

namespace Winche.Secrets;

public static class SecretsServiceCollectionExtensions
{
    /// <summary>
    /// Adds the secret store (<see cref="SecretStore"/>): secrets encrypted with the master key, in the database
    /// <c>AddWincheConfig</c> names (table <c>winche_secrets</c>). Call it after <c>AddWincheConfig</c>; packages that keep
    /// secrets (sign-in, storage locations, functions, webhooks) find it here. Safe to call more than once.
    /// </summary>
    public static IServiceCollection AddWincheSecrets(this IServiceCollection services)
    {
        if (services.Any(d => d.ServiceType == typeof(SecretStore))) return services;
        services.AddSingleton(sp =>
        {
            var config = sp.GetService<WincheConfigOptions>()
                ?? throw new InvalidOperationException("Winche.Secrets keeps secrets where Winche.Core keeps settings: call AddWincheConfig first.");
            return new SecretStore(sp.GetRequiredKeyedService<NpgsqlDataSource>(nameof(WincheConfigOptions)), config.MasterKey, config.PreviousMasterKeys);
        });
        services.AddHostedService<SecretsStartup>();
        return services;
    }
}

/// <summary>Makes the secrets table on start; after a master key change, moves the secrets to the current key.</summary>
internal sealed class SecretsStartup(SecretStore secrets, IServiceProvider services, ILogger<SecretsStartup> logger) : IHostedService
{
    internal static readonly string[] Steps =
    [
        """
            CREATE TABLE IF NOT EXISTS winche_secrets (
              name text PRIMARY KEY,
              ciphertext bytea NOT NULL,
              set_at timestamptz NOT NULL,
              set_by text NULL
            );
        """,
    ];

    public async Task StartAsync(CancellationToken ct)
    {
        await WincheSchema.EnsureAsync(services.GetRequiredKeyedService<NpgsqlDataSource>(nameof(WincheConfigOptions)), "secrets", Steps, ct);
        if (services.GetRequiredService<WincheConfigOptions>().PreviousMasterKeys.Count > 0)
        {
            var moved = await secrets.ReencryptAsync(ct);
            if (moved.Reencrypted > 0) logger.LogInformation("Re-encrypted {Count} secrets with the current master key.", moved.Reencrypted);
            if (moved.Unreadable > 0) logger.LogError("{Count} secrets can't be read with the current or any previous master key.", moved.Unreadable);
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
