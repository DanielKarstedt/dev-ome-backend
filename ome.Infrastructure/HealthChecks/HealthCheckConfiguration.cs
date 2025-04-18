using System.Diagnostics;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using ome.Infrastructure.Persistence.Context;

namespace ome.Infrastructure.HealthChecks;

/// <summary>
/// Provides extension methods for configuring health checks
/// </summary>
public static class HealthCheckConfiguration
{
    private static readonly string[] Builder = ["database", "sql"];
    private static readonly string[] BuilderArray = ["self"];
    private static readonly string[] Tags = ["resources"];
    private static readonly string[] TagsArray = ["external"];

    /// <summary>
    /// Adds comprehensive health checks to the application
    /// </summary>
    public static IServiceCollection AddComprehensiveHealthChecks(
        this IServiceCollection services, 
        IConfiguration configuration)
    {
        services.AddHealthChecks()
            // Database health check
            .AddDbContextCheck<ApplicationDbContext>(
                name: "database", 
                failureStatus: HealthStatus.Unhealthy,
                tags: Builder)
            // Self health check
            .AddCheck("self", () => HealthCheckResult.Healthy(), 
                tags: BuilderArray)
            // Memory usage check
            .AddCheck("memory", () => 
            {
                var memoryLoad = Process.GetCurrentProcess().WorkingSet64;
                const long maxMemoryThreshold = 1024L * 1024 * 1024; // 1GB
                
                return memoryLoad < maxMemoryThreshold
                    ? HealthCheckResult.Healthy()
                    : HealthCheckResult.Degraded($"High memory usage: {memoryLoad / (1024 * 1024)}MB");
            }, tags: Tags)
            
            // Optional: Add more specific checks based on your infrastructure
            .AddCheck("external-services", () => HealthCheckResult.Healthy(), tags: TagsArray);

        return services;
    }

    /// <summary>
    /// Configures detailed health check response options
    /// </summary>
    public static void MapDetailedHealthChecks(this WebApplication app)
    {
        app.MapHealthChecks("/api/health", new HealthCheckOptions
        {
            ResponseWriter = async (context, report) =>
            {
                context.Response.ContentType = "application/json";
                
                var result = new
                {
                    Status = report.Status.ToString(),
                    report.TotalDuration,
                    Checks = report.Entries.Select(entry => new
                    {
                        Name = entry.Key,
                        Status = entry.Value.Status.ToString(),
                        entry.Value.Description,
                        entry.Value.Duration
                    }),
                    Timestamp = DateTime.UtcNow
                };

                await context.Response.WriteAsJsonAsync(result);
            },
            AllowCachingResponses = false
        });
    }
}