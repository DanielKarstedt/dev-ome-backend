using ome.Core.Domain.Entities.Common;
using ome.Core.Domain.Entities.Tenants;
using ome.Core.Domain.Enums;

namespace ome.Core.Domain.Entities.Users {
    /// <summary>
    /// Repräsentiert einen Benutzer im System
    /// </summary>
    public class User : TenantEntity {
        
        /// <summary>
        /// Keycloak User ID (sub)
        /// </summary>
        public string KeycloakId { get; init; } = null!;

        /// <summary>
        /// Benutzername
        /// </summary>
        public string Username { get; set; } = null!;

        /// <summary>
        /// E-Mail-Adresse
        /// </summary>
        public string Email { get; set; } = null!;

        /// <summary>
        /// Vorname
        /// </summary>
        public string FirstName { get; set; } = null!;

        /// <summary>
        /// Nachname
        /// </summary>
        public string LastName { get; set; } = null!;

        /// <summary>
        /// Zeigt an, ob der Benutzer aktiv ist
        /// </summary>
        public new bool IsActive { get; set; } = true;
        
        /// <summary>
        /// Navigation Property zum Tenant
        /// </summary>
        public Tenant? Tenant { get; init; }

        /// <summary>
        /// Liste der Rollen des Benutzers
        /// </summary>
        public virtual List<UserRole> Roles { get; init; } = [];



        /// <summary>
        /// Zeitpunkt des letzten Logins
        /// </summary>
        public DateTime? LastLoginAt { get; init; }

        /// <summary>
        /// Fügt eine Rolle zum Benutzer hinzu, wenn sie noch nicht existiert
        /// </summary>
        public void AddRole(RoleType role) {
            var roleString = role.ToString();

            if (!HasRole(role)) {
                Roles.Add(new UserRole {
                    RoleName = roleString,
                    UserId = Id,
                    TenantId = TenantId
                });
            }
        }


        /// <summary>
        /// Entfernt eine Rolle vom Benutzer
        /// </summary>
        public void RemoveRole(RoleType role) {
            var roleString = role.ToString();
            var existingRole = Roles.Find(r => r.RoleName == roleString);

            if (existingRole != null) {
                Roles.Remove(existingRole);
            }
        }

        /// <summary>
        /// Prüft, ob der Benutzer eine bestimmte Rolle hat
        /// </summary>
        public bool HasRole(RoleType role) {
            var roleString = role.ToString();
            return Roles.Exists(r => r.RoleName == roleString);
        }
    }
}