using HotChocolate;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Logging.Filters;

/// <summary>
/// Filter zur Behandlung von GraphQL-Fehler
/// </summary>
public class GraphQlErrorFilter(
    ILogger<GraphQlErrorFilter> logger,
    IServiceProvider serviceProvider)
    : IErrorFilter 
{
    public IError OnError(IError error) 
    {
        // Null-Prüfungen hinzufügen
        if (error == null!)
        {
            logger.LogWarning("Ein null-Fehler wurde übergeben");
            return CreateDefaultError();
        }

        // Tenant-ID sicher abrufen
        var tenantId = Guid.Empty;
        try
        {
            using var scope = serviceProvider.CreateScope();
            var tenantService = scope.ServiceProvider.GetRequiredService<ITenantService>();
            tenantId = tenantService.GetCurrentTenantId();
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Fehler beim Abrufen der Tenant-ID");
        }

        var exception = error.Exception;

        if (exception != null)
        {
            logger.LogError(exception, "GraphQL-Fehler für Tenant {TenantId}: {ErrorMessage}", 
                tenantId, error.Message);
        }
        else
        {
            logger.LogWarning("GraphQL-Fehler für Tenant {TenantId}: {ErrorMessage}", 
                tenantId, error.Message);
        }

        // Bei Produktionsumgebung, maskiere interne Fehlerdetails
        return error.Path?.IsRoot == true ? error : HandleSpecificExceptions(error);
    }

    private static IError HandleSpecificExceptions(IError error)
    {
        var exception = error.Exception;
        
        if (exception == null)
        {
            return CreateDefaultError();
        }

        return exception switch
        {
            UnauthorizedAccessException => CreateError(
                "Sie sind nicht berechtigt, diese Operation auszuführen.", 
                "UNAUTHORIZED"),
            
            InvalidOperationException => CreateError(
                "Die Anfrage konnte nicht verarbeitet werden.", 
                "BAD_REQUEST"),
            
            _ => CreateDefaultError()
        };
    }

    private static IError CreateError(string message, string errorCode, IError? originalError = null!)
    {
        return originalError?.WithMessage(message)
            .WithExtensions(new Dictionary<string, object>
            {
                { "code", errorCode }
            }!) ?? ErrorBuilder.New()
            .SetMessage(message)
            .SetExtension("code", errorCode)
            .Build();
    }

    private static IError CreateDefaultError()
    {
        return ErrorBuilder.New()
            .SetMessage("Ein unerwarteter Fehler ist aufgetreten.")
            .SetExtension("code", "INTERNAL_SERVER_ERROR")
            .Build();
    }
}