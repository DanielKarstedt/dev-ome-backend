using ome.Core.Domain.Entities.Common;

namespace ome.Core.Domain.Entities.Users;

/// <summary>
/// Repräsentiert eine Benutzerrolle
/// </summary>
public class UserRole: TenantEntity {
    public Guid UserId { get; init; }
    public string RoleName { get; init; } = null!;
}