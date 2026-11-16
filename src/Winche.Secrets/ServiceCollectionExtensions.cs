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
    /// <c>AddWincheConfig</c> names (table <c>winche_secrets</c>). Packages that keep secrets (sign-in, storage locations,
    /// functions, webhooks) call it themselves; calling it again does nothing. Without <c>AddWincheConfig</c> the store
    /// is there but unavailable (<see cref="SecretStore.Available"/> false: nothing is set, nothing can be saved).
    /// </summary>
    public static IServiceCollection AddWincheSecrets(this IServiceCollection services, Action<WincheSecretsOptions>? configure = null)
    {
        var options = services.FirstOrDefault(d => d.ServiceType == typeof(WincheSecretsOptions))?.ImplementationInstance as WincheSecretsOptions;
        if (options is null)
        {
            options = new WincheSecretsOptions();
            services.AddSingleton(options);
            services.AddSingleton(sp => sp.GetService<WincheConfigOptions>() is { } config
                ? new SecretStore(sp.GetRequiredKeyedService<NpgsqlDataSource>(nameof(WincheConfigOptions)), config.MasterKey, config.PreviousMasterKeys,
                    sp.GetServices<ISecretSource>(), options, sp.GetService<TimeProvider>())
                : new SecretStore(null, null, sources: sp.GetServices<ISecretSource>(), options: options));
            services.AddHostedService<SecretsStartup>();
        }
        configure?.Invoke(options);
        return services;
    }

    /// <summary>
    /// Lets references read from <typeparamref name="T"/> (a source package's <c>AddWincheSecrets…()</c> calls this).
    /// Adds the secret store too. A source registered twice by name: the last one counts.
    /// </summary>
    public static IServiceCollection AddWincheSecretSource<T>(this IServiceCollection services) where T : class, ISecretSource
    {
        services.AddWincheSecrets();
        if (!services.Any(d => d.ServiceType == typeof(ISecretSource) && d.ImplementationType == typeof(T)))
            services.AddSingleton<ISecretSource, T>();
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
        // References: a row is a value (ciphertext) or where to read one (reference).
        """
            ALTER TABLE winche_secrets ALTER COLUMN ciphertext DROP NOT NULL;
            ALTER TABLE winche_secrets ADD COLUMN IF NOT EXISTS reference text NULL;
            ALTER TABLE winche_secrets ADD COLUMN IF NOT EXISTS app_credentials boolean NOT NULL DEFAULT false;
        """,
    ];

    public async Task StartAsync(CancellationToken ct)
    {
        if (services.GetService<WincheConfigOptions>() is not { } config) return;   // no settings database: nothing to keep
        await WincheSchema.EnsureAsync(services.GetRequiredKeyedService<NpgsqlDataSource>(nameof(WincheConfigOptions)), "secrets", Steps, ct);
        if (config.PreviousMasterKeys.Count > 0)
        {
            var moved = await secrets.ReencryptAsync(ct);
            if (moved.Reencrypted > 0) logger.LogInformation("Re-encrypted {Count} secrets with the current master key.", moved.Reencrypted);
            if (moved.Unreadable > 0) logger.LogError("{Count} secrets can't be read with the current or any previous master key.", moved.Unreadable);
        }
    }

    public Task StopAsync(CancellationToken ct) => Task.CompletedTask;
}
