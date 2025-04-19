using ome.Core.Domain.Entities.Tenants;
using ome.Core.Domain.Entities.Users;

namespace ome.Core.Domain.Entities.Common
{
    /// <summary>
    /// Repräsentiert einen Tenant (Unternehmen/Organisation) im Multi-Tenant-System
    /// </summary>
    public class TenantEntity : BaseEntity, IAggregateRoot
    {
        /// <summary>
        /// Technischer Name des Tenants (slug)
        /// </summary>
        public string Name { get; set; } = null!;
        
        /// <summary>
        /// Anzeigename des Tenants
        /// </summary>
        public string DisplayName { get; set; } = null!;
        
        /// <summary>
        /// Beschreibung des Tenants
        /// </summary>
        public string? Description { get; set; }
        
        /// <summary>
        /// Logo/Bild-URL des Tenants
        /// </summary>
        public string? LogoUrl { get; set; }
        
        /// <summary>
        /// Primäre Farbe für Tenant-spezifisches Branding
        /// </summary>
        public string? PrimaryColor { get; set; }
        
        /// <summary>
        /// Sekundäre Farbe für Tenant-spezifisches Branding
        /// </summary>
        public string? SecondaryColor { get; set; }
        
        /// <summary>
        /// Zeigt an, ob der Tenant aktiv ist
        /// </summary>
        public bool IsActive { get; set; } = true;
        
        /// <summary>
        /// Connection-String für die Tenant-Datenbank
        /// Bei Shared-Database-Ansatz kann dies null sein
        /// </summary>
        public string? ConnectionString { get; set; }
        
        /// <summary>
        /// Navigation Property zu den Benutzern dieses Tenants
        /// </summary>
        public virtual List<User> Users { get; set; } = [];
        
        /// <summary>
        /// Ablaufdatum des Tenants (optional)
        /// </summary>
        public DateTime? ExpiresAt { get; set; }
        
        /// <summary>
        /// Keycloak-Konfiguration für den Tenant
        /// </summary>
        public TenantKeycloakSettings? KeycloakSettings { get; set; }
        
        /// <summary>
        ///  Die Foreign Key Property, die direkt auf die TenantId in der Datenbank verweist
        /// </summary>
        public Guid TenantId { get; set; } = Guid.Empty;
    }
    
    /// <summary>
    /// Keycloak-Konfiguration für einen spezifischen Tenant
    /// </summary>
    public class TenantKeycloakSettings : BaseEntity
    {
        /// <summary>
        /// Realm-Name in Keycloak
        /// </summary>
        public string Realm { get; set; } = null!;
        
        /// <summary>
        /// Client-ID in Keycloak
        /// </summary>
        public string ClientId { get; set; } = null!;
        
        /// <summary>
        /// Client-Secret für vertrauliche Clients
        /// </summary>
        public string? ClientSecret { get; set; }
        
        /// <summary>
        /// Navigation Property zum Tenant
        /// </summary>
        public virtual Tenant? Tenant { get; set; }
    }
}
