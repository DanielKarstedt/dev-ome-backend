using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using ome.Infrastructure.Logging.Enrichers;
using Serilog;
using Serilog.Events;
using Serilog.Exceptions;
using Serilog.Filters;
using Serilog.Sinks.SystemConsole.Themes;

namespace ome.Infrastructure.Logging;

/// <summary>
/// Konfiguration für Serilog
/// </summary>
public static class SerilogConfiguration {
    /// <summary>
    /// Konfiguriert Serilog für die Anwendung
    /// </summary>
    public static WebApplicationBuilder ConfigureSerilog(this WebApplicationBuilder builder) {
        builder.Host.UseSerilog(ConfigureLogger);

        return builder;
    }

    private static void ConfigureLogger(
        HostBuilderContext context,
        IServiceProvider services,
        LoggerConfiguration configuration) {
        var env = context.HostingEnvironment;
        var config = context.Configuration;

        // Basis-Konfiguration
        configuration
            .ReadFrom.Configuration(config)
            .ReadFrom.Services(services)
            .Enrich.FromLogContext()
            .Enrich.WithMachineName()
            .Enrich.WithEnvironmentName()
            .Enrich.WithExceptionDetails()
            .Enrich.With<TenantIdEnricher>() // Custom Enricher für TenantId
            .Enrich.WithProperty("Application", env.ApplicationName)
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.AspNetCore.Authentication", LogEventLevel.Information);

        // GraphQL Logging konfigurieren
        configuration.MinimumLevel.Override("HotChocolate", LogEventLevel.Information);
        configuration.MinimumLevel.Override("HotChocolate.Execution", LogEventLevel.Information);
        configuration.MinimumLevel.Override("HotChocolate.Execution.Batching", LogEventLevel.Information);
        configuration.MinimumLevel.Override("HotChocolate.Execution.Processing", LogEventLevel.Information);
        configuration.MinimumLevel.Override("HotChocolate.Subscriptions", LogEventLevel.Information);

        // Entwicklungsumgebung: Konsole mit detaillierten Logs
        if (env.IsDevelopment())
        {
            configuration
                .MinimumLevel.Debug()
                .WriteTo.Console(
                    outputTemplate:
                    "[{Timestamp:HH:mm:ss} {Level:u3}] [{TenantId}] [{SourceContext}] {Message:lj}{NewLine}{Exception}",
                    theme: AnsiConsoleTheme.Code,
                    restrictedToMinimumLevel: LogEventLevel.Debug);
        }
        // Produktionsumgebung: Strukturierte Logs
        else
        {
            var seqServerUrl = config["Logging:Seq:ServerUrl"];

            if (!string.IsNullOrWhiteSpace(seqServerUrl))
            {
                configuration.WriteTo.Seq(
                    seqServerUrl,
                    restrictedToMinimumLevel: LogEventLevel.Information);
            }

            // JSON-Logs für Container-Umgebungen
            configuration.WriteTo.Console(new Serilog.Formatting.Json.JsonFormatter());
        }

        // Tenant-spezifische Logs für Admin-Dashboard
        // Diese werden später über einen custom Sink an das Admin-Dashboard gesendet
        configuration.WriteTo.Logger(lc => lc
            .Filter.ByIncludingOnly(Matching.WithProperty("TenantId"))
            .WriteTo.File(
                path: $"logs/tenant-.log",
                rollingInterval: RollingInterval.Day,
                outputTemplate:
                "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] [{TenantId}] {Message:lj}{NewLine}{Exception}",
                restrictedToMinimumLevel: LogEventLevel.Information
            )
        );
    }
}