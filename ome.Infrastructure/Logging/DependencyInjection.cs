using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using System.Globalization;
using HotChocolate;
using ome.Infrastructure.Logging.Enrichers;
using ome.Infrastructure.Logging.Sinks;
using Serilog;
using Microsoft.Extensions.Options;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Identity.Keycloak;
using ome.Infrastructure.Logging.Filters;

namespace ome.Infrastructure.Logging;

public class GraphQlSubscriptionSinkOptions {
    public bool EnableDetailedLogging { get; init; }
}

public static class DependencyInjection {
    public static IServiceCollection AddLoggingServices(
        this IServiceCollection services,
        IConfiguration configuration) {
        // Konfigurationsoptionen
        services.Configure<GraphQlSubscriptionSinkOptions>(
            configuration.GetSection("Logging:GraphQlSink")
        );

        services.AddSingleton<IFormatProvider>(CultureInfo.InvariantCulture);
        services.AddMemoryCache();

        // GraphQL Sink mit Optionen
        services.AddSingleton<GraphQlSubscriptionSink>(sp =>
        {
            var formatProvider = sp.GetRequiredService<IFormatProvider>();
            var logger = sp.GetRequiredService<ILogger<GraphQlSubscriptionSink>>();
            var options = sp.GetRequiredService<IOptions<GraphQlSubscriptionSinkOptions>>();

            return new GraphQlSubscriptionSink(formatProvider, logger, options.Value);
        });

        services.AddScoped<GraphQlLogProvider>();
        
        services.AddSingleton<IErrorFilter, GraphQlErrorFilter>();

        services.AddHttpClient<IKeycloakService, KeycloakService>();

        // Serilog Konfiguration
        services.AddSingleton(provider =>
        {
            var logSink = provider.GetRequiredService<GraphQlSubscriptionSink>();
            var requiredService = provider.GetRequiredService<IConfiguration>();

            return new LoggerConfiguration()
                .ReadFrom.Configuration(requiredService)
                .WriteTo.Sink(logSink)
                .CreateLogger();
        });

        services.AddSingleton<TenantIdEnricher>(provider =>
            new TenantIdEnricher(provider));

        return services;
    }
}