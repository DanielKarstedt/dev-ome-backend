using ome.Core.Domain.Entities.Common;

namespace ome.Core.Domain.Entities.Tenants;

/// <summary>
/// Repräsentiert einen Mandanten/Tenant im System
/// </summary>
public class Tenant: BaseEntity, IAggregateRoot {
    public string Name { get; init; } = null!;
    public string DisplayName { get; init; } = null!;
    public string KeycloakGroupId { get; init; } = null!;
    public bool IsActive { get; init; } = true;
    public string? ConnectionString { get; init; }
}