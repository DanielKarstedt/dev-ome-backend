using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Tenants;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Persistence.Context;

namespace ome.Infrastructure.Identity.Services;

public class TenantService(
    IHttpContextAccessor httpContextAccessor,
    ILogger<TenantService> logger,
    IDbContextFactory<ApplicationDbContext> dbContextFactory)
    : ITenantService {
    public Guid GetCurrentTenantId()
    {
        try 
        {
            var httpContext = httpContextAccessor.HttpContext;
            if (httpContext?.User == null)
            {
                logger.LogWarning("Keine HTTP-Kontext oder Benutzer gefunden");
                return Guid.Empty;
            }

            // Hole alle Gruppen aus den Claims
            var groups = httpContext.User.FindAll("groups")
                .Select(c => c.Value)
                .ToList();

            logger.LogInformation("Gefundene Gruppen: {Groups}", string.Join(", ", groups));

            // Suche nach Gruppe, die mit "tenant:" beginnt
            foreach (var group in groups)
            {
                if (group.StartsWith("tenant:", StringComparison.OrdinalIgnoreCase))
                {
                    var tenantIdPart = group.Split(':').LastOrDefault();
                    
                    if (Guid.TryParse(tenantIdPart, out var tenantId))
                    {
                        logger.LogInformation("Tenant ID aus Gruppe extrahiert: {TenantId}", tenantId);
                        return tenantId;
                    }
                }
            }

            logger.LogWarning("Keine Tenant ID in Gruppen gefunden");
            return Guid.Empty;
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Fehler beim Ermitteln der aktuellen Tenant ID");
            return Guid.Empty;
        }
    }

    public void SetCurrentTenantId(Guid tenantId)
    {
        // In einer Keycloak-basierten Anwendung ist dies normalerweise nicht notwendig
        logger.LogInformation("Manuelles Setzen der Tenant ID: {TenantId}", tenantId);
    }

    public async Task<Tenant?> GetCurrentTenantAsync(CancellationToken cancellationToken = default)
    {
        var tenantId = GetCurrentTenantId();
        if (tenantId == Guid.Empty)
            return null;

        // Hier DbContext über Factory erstellen
        await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => 
                t.Id == tenantId && 
                t.IsActive && 
                !t.IsDeleted, 
            cancellationToken);
    }

    public async Task<string?> GetConnectionStringAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        // Hier DbContext über Factory erstellen
        await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
        var tenant = await dbContext.Tenants
            .AsNoTracking()
            .FirstOrDefaultAsync(t => 
                t.Id == tenantId && 
                t.IsActive && 
                !t.IsDeleted, 
            cancellationToken);

        return tenant?.ConnectionString;
    }

    public async Task<bool> TenantExistsAsync(Guid tenantId, CancellationToken cancellationToken = default)
    {
        // Hier DbContext über Factory erstellen
        await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
        return await dbContext.Tenants
            .AsNoTracking()
            .AnyAsync(t => 
                t.Id == tenantId && 
                t.IsActive && 
                !t.IsDeleted, 
            cancellationToken);
    }

    public async Task<bool> InitializeTenantContextAsync(string companyId, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrEmpty(companyId))
        {
            logger.LogWarning("Ungültige leere Company ID");
            return false;
        }

        // Versuche, die Company ID als GUID zu parsen
        if (Guid.TryParse(companyId, out var tenantId))
        {
            return await TenantExistsAsync(tenantId, cancellationToken);
        }

        // Hier DbContext über Factory erstellen
        await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
        // Suche nach Tenant mit Name oder DisplayName
        var normalizedCompanyId = companyId.ToUpperInvariant();
        var tenant = await dbContext.Tenants
            .AsNoTracking()
            .IgnoreQueryFilters()
            .FirstOrDefaultAsync(t => 
                (t.Name.Equals(normalizedCompanyId, StringComparison.CurrentCultureIgnoreCase) || 
                 t.DisplayName.Equals(normalizedCompanyId, StringComparison.CurrentCultureIgnoreCase)) &&
                 t.IsActive && 
                !t.IsDeleted, 
            cancellationToken);

        return tenant != null;
    }
}