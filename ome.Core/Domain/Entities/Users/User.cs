using ome.Core.Domain.Entities.Common;
using ome.Core.Domain.Enums;

namespace ome.Core.Domain.Entities.Users;

/// <summary>
/// Repräsentiert einen Benutzer im System
/// </summary>
public class User: TenantEntity, IAggregateRoot {
    public string KeycloakId { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string FirstName { get; set; } = null!;
    public string LastName { get; set; } = null!;
    public bool IsActive { get; set; } = true;
    public List<UserRole> Roles { get; init; } = [];

    /// <summary>
    /// Fügt eine Rolle zum Benutzer hinzu, wenn sie noch nicht existiert
    /// </summary>
    public void AddRole(RoleType role) {
        var roleString = role.ToString();

        if (!HasRole(role))
        {
            Roles.Add(new UserRole
            {
                RoleName = roleString,
                TenantId = this.TenantId
            });
        }
    }

    /// <summary>
    /// Entfernt eine Rolle vom Benutzer
    /// </summary>
    public void RemoveRole(RoleType role) {
        var roleString = role.ToString();
        var existingRole = Roles.Find(r => r.RoleName == roleString);

        if (existingRole != null)
        {
            Roles.Remove(existingRole);
        }
    }

    /// <summary>
    /// Prüft, ob der Benutzer eine bestimmte Rolle hat
    /// </summary>
    private bool HasRole(RoleType role) {
        var roleString = role.ToString();
        return Roles.Exists(r => r.RoleName == roleString);
    }
}