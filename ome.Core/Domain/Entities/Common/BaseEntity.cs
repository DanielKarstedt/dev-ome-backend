namespace ome.Core.Domain.Entities.Common;

/// <summary>
/// Basisklasse für alle Entitäten
/// </summary>
public class BaseEntity {
    public Guid Id { get; init; }
    public DateTime CreatedAt { get; set; }
    public string CreatedBy { get; set; } = null!;
    public DateTime? LastModifiedAt { get; set; }
    public string LastModifiedBy { get; set; } = null!;
    public bool IsDeleted { get; set; } = false;
}