using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using ome.Core.Interfaces.Services;
using ome.Core.Domain.Entities.Tenants;

namespace ome.Infrastructure.Persistence.Context;

// Implementierung des ITenantService für Design-Time
public class DesignTimeTenantService : ITenantService {
    public Guid GetCurrentTenantId() => Guid.Empty;

    public void SetCurrentTenantId(Guid tenantId) {
        // Design-Time-Implementation: nichts tun
    }

    public Task<Tenant?> GetCurrentTenantAsync(CancellationToken cancellationToken = default) {
        // Rückgabe eines null Tenants für Design-Time
        return Task.FromResult<Tenant?>(null);
    }

    public Task<string?> GetConnectionStringAsync(Guid tenantId, CancellationToken cancellationToken = default) {
        // Rückgabe eines null ConnectionStrings für Design-Time
        return Task.FromResult<string?>(null);
    }

    public Task<bool> TenantExistsAsync(Guid tenantId, CancellationToken cancellationToken = default) {
        // Für Design-Time: Tenant existiert immer
        return Task.FromResult(true);
    }

    public Task<bool> InitializeTenantContextAsync(string companyId, CancellationToken cancellationToken = default) {
        // Für Design-Time: Initialisierung immer erfolgreich
        return Task.FromResult(true);
    }
}

public class ApplicationDbContextFactory : IDesignTimeDbContextFactory<ApplicationDbContext> {
    // Rest des Codes bleibt unverändert
    public ApplicationDbContext CreateDbContext(string[] args) {
        // Build configuration
        var configuration = new ConfigurationBuilder()
            .SetBasePath(Directory.GetCurrentDirectory())
            .AddJsonFile("appsettings.json")
            .AddJsonFile("appsettings.Development.json", optional: true)
            .AddEnvironmentVariables()
            .Build();

        // Configure DbContext options
        var connectionString = configuration.GetConnectionString("DefaultConnection");

        if (string.IsNullOrWhiteSpace(connectionString)) {
            throw new InvalidOperationException("Connection string 'DefaultConnection' is missing or empty.");
        }

        // Replace environment variables in connection string
        connectionString = connectionString
            .Replace("${DB_HOST}", Environment.GetEnvironmentVariable("DB_HOST") ?? "localhost")
            .Replace("${DB_PORT}", Environment.GetEnvironmentVariable("DB_PORT") ?? "5432")
            .Replace("${DB_NAME}", Environment.GetEnvironmentVariable("DB_NAME") ?? "mydatabase")
            .Replace("${DB_USER}", Environment.GetEnvironmentVariable("DB_USER") ?? "myuser")
            .Replace("${DB_PASSWORD}", Environment.GetEnvironmentVariable("DB_PASSWORD") ?? "");

        var optionsBuilder = new DbContextOptionsBuilder<ApplicationDbContext>();

        // Use PostgreSQL with robust configuration matching the Program.cs approach
        optionsBuilder.UseNpgsql(
            connectionString,
            npgsqlOptions => {
                // Migrations Assembly
                npgsqlOptions.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName);

                // Retry mechanism
                npgsqlOptions.EnableRetryOnFailure(
                    maxRetryCount: 5,
                    maxRetryDelay: TimeSpan.FromSeconds(30),
                    errorCodesToAdd: null
                );

                // Performance & Stability Optimizations
                npgsqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
                npgsqlOptions.CommandTimeout(120); // 2 minutes timeout
            }
        );

        // Enable sensitive data logging and detailed errors for design-time
        optionsBuilder.EnableSensitiveDataLogging();
        optionsBuilder.EnableDetailedErrors();

        // Use the constructor that takes only DbContextOptions
        return new ApplicationDbContext(
            optionsBuilder.Options,
            new DesignTimeTenantService(),
            NullLogger<ApplicationDbContext>.Instance
        );
    }
}