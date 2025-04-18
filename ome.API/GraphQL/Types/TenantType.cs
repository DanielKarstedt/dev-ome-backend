using ome.Core.Domain.Entities.Tenants;

namespace ome.API.GraphQL.Types;

/// <summary>
/// GraphQL-Typ für Tenant-Entität
/// </summary>
public class TenantType: ObjectType<Tenant> {
    protected override void Configure(IObjectTypeDescriptor<Tenant> descriptor) {
        descriptor.Description("Repräsentiert einen Mandanten im System");

        descriptor.Field(t => t.Id)
            .Description("Die eindeutige ID des Mandanten");

        descriptor.Field(t => t.Name)
            .Description("Der Name des Mandanten");

        descriptor.Field(t => t.DisplayName)
            .Description("Der Anzeigename des Mandanten");

        descriptor.Field(t => t.KeycloakGroupId)
            .Description("Die Keycloak-Gruppen-ID des Mandanten");

        descriptor.Field(t => t.IsActive)
            .Description("Gibt an, ob der Mandant aktiv ist");

        descriptor.Field(t => t.CreatedAt)
            .Description("Zeitpunkt der Erstellung");

        descriptor.Field(t => t.CreatedBy)
            .Description("Benutzer, der den Eintrag erstellt hat");

        descriptor.Field(t => t.LastModifiedAt)
            .Description("Zeitpunkt der letzten Änderung");

        descriptor.Field(t => t.LastModifiedBy)
            .Description("Benutzer, der den Eintrag zuletzt geändert hat");

        // Verstecke sensible Daten für GraphQL-Clients
        descriptor.Ignore(t => t.ConnectionString);
        descriptor.Ignore(t => t.IsDeleted);
    }
}