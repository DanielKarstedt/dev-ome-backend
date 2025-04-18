using ome.Core.Domain.Entities.Tenants;

namespace ome.Core.Interfaces.Services;

/// <summary>
/// Service zum Zugriff auf Tenant-Informationen
/// </summary>
public interface ITenantService {
    /// <summary>
    /// Gibt die aktuelle Tenant-ID zurück
    /// </summary>
    Guid GetCurrentTenantId();

    /// <summary>
    /// Setzt die aktuelle Tenant-ID
    /// </summary>
    void SetCurrentTenantId(Guid tenantId);

    /// <summary>
    /// Gibt den aktuellen Tenant zurück
    /// </summary>
    Task<Tenant?> GetCurrentTenantAsync(CancellationToken cancellationToken = default);

    /// <summary>
    /// Gibt den Connection String für einen bestimmten Tenant zurück
    /// </summary>
    Task<string?> GetConnectionStringAsync(Guid tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Prüft, ob ein Tenant existiert
    /// </summary>
    Task<bool> TenantExistsAsync(Guid tenantId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Initialisiert den Tenant-Kontext basierend auf der übergebenen Company ID
    /// </summary>
    Task<bool> InitializeTenantContextAsync(string companyId, CancellationToken cancellationToken = default);
}