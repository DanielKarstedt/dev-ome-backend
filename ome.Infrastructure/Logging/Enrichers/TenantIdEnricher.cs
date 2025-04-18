using Microsoft.Extensions.DependencyInjection;
using ome.Core.Interfaces.Services;
using Serilog.Core;
using Serilog.Events;

namespace ome.Infrastructure.Logging.Enrichers;

/// <summary>
/// Enricher, der jedem Log-Eintrag die TenantId hinzufügt
/// </summary>
public class TenantIdEnricher: ILogEventEnricher {
    private readonly IServiceProvider _serviceProvider = null!;
    private const string TenantIdPropertyName = "TenantId";

    public TenantIdEnricher() {
    }

    // Für benutzerdefinierte DI
    public TenantIdEnricher(IServiceProvider serviceProvider) {
        _serviceProvider = serviceProvider;
    }

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory) {
        if (logEvent.Properties.ContainsKey(TenantIdPropertyName))
            return;

        // Versuche, die TenantId aus dem aktuellen Kontext zu holen
        try
        {
            Guid? tenantId = null;

            // Wenn ein ServiceProvider vorhanden ist, versuche, den TenantService zu nutzen
            using (var scope = _serviceProvider.CreateScope())
            {
                var tenantService = scope.ServiceProvider.GetService<ITenantService>();

                if (tenantService != null)
                {
                    tenantId = tenantService.GetCurrentTenantId();
                }
            }

            // Wenn eine TenantId gefunden wurde, füge sie dem Log hinzu
            if (!tenantId.HasValue || tenantId.Value == Guid.Empty)
            {
                return;
            }

            var tenantIdProperty = propertyFactory.CreateProperty(TenantIdPropertyName, tenantId.Value.ToString());
            logEvent.AddPropertyIfAbsent(tenantIdProperty);
        }
        catch (Exception)
        {
            // Bei Fehlern beim Enrichment nicht den Logging-Prozess unterbrechen
        }
    }
}