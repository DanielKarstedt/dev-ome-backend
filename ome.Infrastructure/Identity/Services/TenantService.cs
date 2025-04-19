using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Tenants;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Persistence.Context;
using Npgsql;

namespace ome.Infrastructure.Identity.Services
{
    public class TenantService(
        IHttpContextAccessor httpContextAccessor,
        ILogger<TenantService> logger,
        IDbContextFactory<ApplicationDbContext> dbContextFactory)
        : ITenantService {
        // Zwischenspeicher für die aktuelle Tenant-ID
        private Guid _currentTenantId = Guid.Empty;

        /// <summary>
        /// Ermittelt die Tenant-ID des aktuellen Benutzers aus den Gruppen-Claims
        /// </summary>
        public Guid GetCurrentTenantId()
        {
            // Wenn bereits eine Tenant-ID gesetzt wurde, diese zurückgeben
            if (_currentTenantId != Guid.Empty)
            {
                return _currentTenantId;
            }

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
                foreach (var tenantIdPart in from @group in groups where @group.StartsWith("tenant:", StringComparison.OrdinalIgnoreCase) select @group.Split(':').LastOrDefault()) {
                    if (!Guid.TryParse(tenantIdPart, out var tenantId)) continue;
                    logger.LogInformation("Tenant ID aus Gruppe extrahiert: {TenantId}", tenantId);
                    _currentTenantId = tenantId;
                    return tenantId;
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

        /// <summary>
        /// Setzt die aktuelle Tenant-ID manuell (z.B. für Tests oder spezielle Szenarien)
        /// </summary>
        public void SetCurrentTenantId(Guid tenantId)
        {
            logger.LogInformation("Setze Tenant ID manuell: {TenantId}", tenantId);
            _currentTenantId = tenantId;
        }

        /// <summary>
        /// Holt den aktuellen Tenant aus der Datenbank
        /// </summary>
        public async Task<Tenant?> GetCurrentTenantAsync(CancellationToken cancellationToken = default)
        {
            var tenantId = GetCurrentTenantId();
            if (tenantId == Guid.Empty)
            {
                return null;
            }

            await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
            try
            {
                return await dbContext.Tenants
                    .AsNoTracking()
                    .FirstOrDefaultAsync(t => 
                        t.Id == tenantId && 
                        t.IsActive && 
                        !t.IsDeleted, 
                    cancellationToken);
            }
            catch (Exception ex) when (IsMissingTableException(ex))
            {
                logger.LogWarning(ex, "Tenants-Tabelle fehlt. Falls in Entwicklung, automatisch erstellen.");
                if (!IsDevEnvironment()) return null;
                await CreateTenantsTableIfNotExistsAsync(cancellationToken);
                // In der Entwicklung einen Dummy-Tenant zurückgeben
                return new Tenant
                {
                    Id = tenantId,
                    Name = "Development",
                    DisplayName = "Development Tenant",
                    IsActive = true,
                    IsDeleted = false
                };
            }
        }

        /// <summary>
        /// Stellt sicher, dass die Tenant-Tabelle existiert und erstellt sie bei Bedarf
        /// </summary>
        private async Task CreateTenantsTableIfNotExistsAsync(CancellationToken cancellationToken = default)
        {
            try
            {
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
                await dbContext.Database.ExecuteSqlRawAsync(@"
                    CREATE TABLE IF NOT EXISTS ""Tenants"" (
                        ""Id"" uuid NOT NULL,
                        ""Name"" character varying(100) NOT NULL,
                        ""DisplayName"" character varying(200) NOT NULL, 
                        ""IsActive"" boolean NOT NULL,
                        ""IsDeleted"" boolean NOT NULL,
                        ""ConnectionString"" text NULL,
                        CONSTRAINT ""PK_Tenants"" PRIMARY KEY (""Id"")
                    );", cancellationToken);
                
                logger.LogInformation("Tenants-Tabelle erfolgreich erstellt oder bereits vorhanden");
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Fehler beim Erstellen der Tenants-Tabelle");
                throw;
            }
        }

        /// <summary>
        /// Holt den Connection-String für einen bestimmten Tenant
        /// </summary>
        public async Task<string?> GetConnectionStringAsync(Guid tenantId, CancellationToken cancellationToken = default)
        {
            try
            {
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
            catch (Exception ex) when (IsMissingTableException(ex))
            {
                logger.LogWarning(ex, "Tenants-Tabelle fehlt. Falls in Entwicklung, Connection-String aus Konfiguration verwenden.");
                return null;
            }
        }

        /// <summary>
        /// Prüft, ob ein bestimmter Tenant existiert
        /// </summary>
        public async Task<bool> TenantExistsAsync(Guid tenantId, CancellationToken cancellationToken = default)
        {
            try
            {
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
                return await dbContext.Tenants
                    .AsNoTracking()
                    .AnyAsync(t => 
                        t.Id == tenantId && 
                        t.IsActive && 
                        !t.IsDeleted, 
                    cancellationToken);
            }
            catch (Exception ex) when (IsMissingTableException(ex))
            {
                logger.LogWarning(ex, "Tenants-Tabelle fehlt. Falls in Entwicklung, immer true zurückgeben.");
                return IsDevEnvironment();
            }
        }

        /// <summary>
        /// Initialisiert den Tenant-Kontext für die aktuelle Anfrage
        /// </summary>
        public async Task<bool> InitializeTenantContextAsync(string companyId, CancellationToken cancellationToken = default)
        {
            if (string.IsNullOrEmpty(companyId))
            {
                logger.LogWarning("Ungültige leere Company ID");
                return false;
            }

            try
            {
                // Versuche, die Company ID als GUID zu parsen
                if (Guid.TryParse(companyId, out var tenantId))
                {
                    logger.LogInformation("Company ID als GUID erkannt: {TenantId}", tenantId);
                    var exists = await TenantExistsAsync(tenantId, cancellationToken);
                    
                    if (exists)
                    {
                        SetCurrentTenantId(tenantId);
                    }
                    
                    return exists;
                }

                // Wenn es keine GUID ist, nach Name oder DisplayName suchen
                var normalizedCompanyId = companyId.ToLowerInvariant();
                
                await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
                
                try
                {
                    // Suche nach Tenant mit Name oder DisplayName
                    var tenant = await dbContext.Tenants
                        .AsNoTracking()
                        .IgnoreQueryFilters()
                        .FirstOrDefaultAsync(t => 
                            (t.Name.ToLower() == normalizedCompanyId || 
                             t.DisplayName.ToLower() == normalizedCompanyId) &&
                             t.IsActive && 
                            !t.IsDeleted, 
                        cancellationToken);

                    if (tenant != null)
                    {
                        logger.LogInformation("Tenant gefunden: {TenantId} ({TenantName})", tenant.Id, tenant.Name);
                        SetCurrentTenantId(tenant.Id);
                        return true;
                    }
                    
                    // Wenn kein Tenant gefunden wurde, aber wir in der Entwicklungsumgebung sind
                    if (IsDevEnvironment())
                    {
                        // Automatisch einen neuen Tenant erstellen
                        var newTenant = await EnsureTenantExistsForDevelopmentAsync(companyId, cancellationToken);
                        SetCurrentTenantId(newTenant.Id);
                        return true;
                    }
                    
                    logger.LogWarning("Kein passender Tenant für {CompanyId} gefunden", companyId);
                    return false;
                }
                catch (Exception ex) when (IsMissingTableException(ex))
                {
                    logger.LogWarning(ex, "Tenants-Tabelle fehlt. Versuche zu erstellen und einen Tenant hinzuzufügen.");
                    
                    if (IsDevEnvironment())
                    {
                        // Tabelle erstellen und Tenant hinzufügen
                        await CreateTenantsTableIfNotExistsAsync(cancellationToken);
                        var newTenant = await EnsureTenantExistsForDevelopmentAsync(companyId, cancellationToken);
                        SetCurrentTenantId(newTenant.Id);
                        return true;
                    }
                    
                    logger.LogError("Tenants-Tabelle fehlt in Produktionsumgebung.");
                    return false;
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Fehler bei der Tenant-Initialisierung für {CompanyId}", companyId);
                
                // In der Entwicklungsumgebung trotzdem fortfahren
                if (IsDevEnvironment())
                {
                    logger.LogWarning("Entwicklungsumgebung erkannt - fahre trotz Fehler fort");
                    return true;
                }
                
                return false;
            }
        }

        /// <summary>
        /// Erstellt einen Tenant für die Entwicklungsumgebung
        /// </summary>
        private async Task<Tenant> EnsureTenantExistsForDevelopmentAsync(string companyId, CancellationToken cancellationToken = default)
        {
            await using var dbContext = await dbContextFactory.CreateDbContextAsync(cancellationToken);
            
            // Prüfen, ob Tenant bereits existiert
            var tenant = await dbContext.Tenants
                .FirstOrDefaultAsync(t => t.Name.ToLower() == companyId.ToLower(), cancellationToken);
                
            if (tenant != null)
            {
                return tenant;
            }
            
            // Neuen Tenant anlegen
            var newTenant = new Tenant
            {
                Id = Guid.NewGuid(),
                Name = companyId,
                DisplayName = $"{companyId} (Auto-Created)",
                IsActive = true,
                IsDeleted = false
            };
            
            dbContext.Tenants.Add(newTenant);
            await dbContext.SaveChangesAsync(cancellationToken);
            
            logger.LogInformation("Neuer Entwicklungs-Tenant erstellt: {TenantId} ({TenantName})", 
                newTenant.Id, newTenant.Name);
                
            return newTenant;
        }

        /// <summary>
        /// Prüft, ob es sich um eine Entwicklungsumgebung handelt
        /// </summary>
        private bool IsDevEnvironment()
        {
            var env = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
            return string.Equals(env, "Development", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Prüft, ob die Exception durch eine fehlende Tabelle verursacht wurde
        /// </summary>
        private bool IsMissingTableException(Exception ex)
        {
            if (ex is PostgresException pgEx)
            {
                return pgEx.SqlState == "42P01"; // 42P01 = relation does not exist
            }
            
            return ex.ToString().Contains("relation") && 
                   ex.ToString().Contains("does not exist");
        }
    }
}