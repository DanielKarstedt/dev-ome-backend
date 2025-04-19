using ome.Core.Domain.Entities.Common;

namespace ome.Core.Domain.Entities.Users;

/// <summary>
/// Repräsentiert eine Rolle eines Benutzers
/// </summary>
public class UserRole: TenantEntity
{
    /// <summary>
    /// ID des Benutzers
    /// </summary>
    public Guid UserId { get; init; }
        
    /// <summary>
    /// Name der Rolle
    /// </summary>
    public string RoleName { get; init; } = null!;
        
    /// <summary>
    /// Navigation Property zum Benutzer
    /// </summary>
    public virtual User User { get; init; } = null!;

    
}

