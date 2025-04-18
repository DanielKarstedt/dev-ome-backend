namespace ome.Core.Domain.Entities.Common;

/// <summary>
/// Basisklasse für alle tenant-spezifischen Entitäten
/// </summary>
public class TenantEntity: BaseEntity {
    public Guid TenantId { get; set; }
}