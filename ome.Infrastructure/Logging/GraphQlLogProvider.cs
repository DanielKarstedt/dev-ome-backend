using Microsoft.Extensions.Logging;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Logging.Sinks;
using Serilog.Events;

namespace ome.Infrastructure.Logging;

/// <summary>
/// Provider für Logging-Daten über GraphQL
/// </summary>
public class GraphQlLogProvider(
    GraphQlSubscriptionSink logSink,
    ITenantService tenantService,
    ILogger<GraphQlLogProvider> logger) {

    /// <summary>
    /// Gibt die neuesten Logs für den aktuellen Tenant zurück
    /// </summary>
    public async Task<LogEntryDto[]> GetLatestLogsAsync(int maxCount = 100,
        CancellationToken cancellationToken = default) {
        try
        {
            var tenantId = tenantService.GetCurrentTenantId();
            var logs = await logSink.GetLatestLogsForTenantAsync(tenantId, maxCount);

            return ConvertToLogEntryDtos(logs as LogEvent[]);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Fehler beim Abrufen der neuesten Logs über GraphQL");
            return [];
        }
    }

    /// <summary>
    /// Konvertiert Serilog LogEvents in DTOs für GraphQL
    /// </summary>
    private LogEntryDto[] ConvertToLogEntryDtos(LogEvent[]? logEvents) {
        var dtos = new LogEntryDto[logEvents!.Length];

        for (var i = 0; i < logEvents.Length; i++)
        {
            var logEvent = logEvents[i];

            dtos[i] = new LogEntryDto
            {
                Id = Guid.NewGuid(), // In einer echten Implementierung würden wir eine konsistente ID verwenden
                Timestamp = logEvent.Timestamp.UtcDateTime,
                Level = logEvent.Level.ToString(),
                Message = logEvent.RenderMessage(),
                Exception = logEvent.Exception?.ToString()!,
                Properties = ConvertPropertiesToString(logEvent.Properties),
                SourceContext = GetSourceContext(logEvent.Properties)
            };
        }

        return dtos;
    }

    private static string ConvertPropertiesToString(IReadOnlyDictionary<string, LogEventPropertyValue> properties) {
        try
        {
            // Einfache Serialisierung der Eigenschaften für die Anzeige
            var propertiesString = new System.Text.StringBuilder();

            foreach (var property in properties)
            {
                if (property.Key != "SourceContext" && property.Key != "TenantId")
                {
                    propertiesString.Append($"{property.Key}={property.Value.ToString()}, ");
                }
            }

            return propertiesString.ToString().TrimEnd(',', ' ');
        }
        catch
        {
            return string.Empty;
        }
    }

    private static string GetSourceContext(IReadOnlyDictionary<string, LogEventPropertyValue> properties) {
        if (properties.TryGetValue("SourceContext", out var sourceContextProperty) &&
            sourceContextProperty is ScalarValue { Value: string sourceContext })
        {
            return sourceContext;
        }

        return string.Empty;
    }
}

/// <summary>
/// DTO für Log-Einträge in GraphQL
/// </summary>
public class LogEntryDto {
    public Guid Id { get; set; }
    public DateTime Timestamp { get; set; }
    public string Level { get; set; } = null!;
    public string Message { get; set; } = null!;
    public string Exception { get; set; } = null!;
    public string Properties { get; set; } = null!;
    public string SourceContext { get; set; } = null!;
}
