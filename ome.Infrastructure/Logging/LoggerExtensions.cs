using Microsoft.Extensions.Logging;

namespace ome.Infrastructure.Logging;

/// <summary>
/// Erweiterungsmethoden für ILogger
/// </summary>
public static class LoggerExtensions {
    /// <summary>
    /// Loggt eine Nachricht mit Tenant-Kontext
    /// </summary>
    public static void LogWithTenant(
        this ILogger logger,
        LogLevel logLevel,
        Guid tenantId,
        string message,
        params object[] args) {
        using (logger.BeginScope(new { TenantId = tenantId }))
        {
            logger.Log(logLevel, message, args);
        }
    }

    /// <summary>
    /// Loggt eine Debug-Nachricht mit Tenant-Kontext
    /// </summary>
    public static void LogDebugWithTenant(
        this ILogger logger,
        Guid tenantId,
        string message,
        params object[] args) {
        logger.LogWithTenant(LogLevel.Debug, tenantId, message, args);
    }

    /// <summary>
    /// Loggt eine Info-Nachricht mit Tenant-Kontext
    /// </summary>
    public static void LogInformationWithTenant(
        this ILogger logger,
        Guid tenantId,
        string message,
        params object[] args) {
        logger.LogWithTenant(LogLevel.Information, tenantId, message, args);
    }

    /// <summary>
    /// Loggt eine Warning-Nachricht mit Tenant-Kontext
    /// </summary>
    public static void LogWarningWithTenant(
        this ILogger logger,
        Guid tenantId,
        string message,
        params object[] args) {
        logger.LogWithTenant(LogLevel.Warning, tenantId, message, args);
    }

    /// <summary>
    /// Loggt eine Error-Nachricht mit Tenant-Kontext
    /// </summary>
    public static void LogErrorWithTenant(
        this ILogger logger,
        Guid tenantId,
        Exception exception,
        string message,
        params object[] args) {
        using (logger.BeginScope(new { TenantId = tenantId }))
        {
            logger.LogError(exception, message, args);
        }
    }
}