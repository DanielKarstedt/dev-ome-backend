using ome.Core.Domain.Entities.Users;

namespace ome.API.GraphQL.Types;

/// <summary>
/// GraphQL-Typ für User-Entität
/// </summary>
public class UserType: ObjectType<User> {
    protected override void Configure(IObjectTypeDescriptor<User> descriptor) {
        descriptor.Description("Repräsentiert einen Benutzer im System");

        descriptor.Field(u => u.Id)
            .Description("Die eindeutige ID des Benutzers");

        descriptor.Field(u => u.KeycloakId)
            .Description("Die Keycloak-ID des Benutzers");

        descriptor.Field(u => u.Username)
            .Description("Der Benutzername");

        descriptor.Field(u => u.Email)
            .Description("Die E-Mail-Adresse des Benutzers");

        descriptor.Field(u => u.FirstName)
            .Description("Der Vorname des Benutzers");

        descriptor.Field(u => u.LastName)
            .Description("Der Nachname des Benutzers");

        descriptor.Field(u => u.IsActive)
            .Description("Gibt an, ob der Benutzer aktiv ist");

        descriptor.Field(u => u.CreatedAt)
            .Description("Zeitpunkt der Erstellung");

        descriptor.Field(u => u.CreatedBy)
            .Description("Benutzer, der den Eintrag erstellt hat");

        descriptor.Field(u => u.LastModifiedAt)
            .Description("Zeitpunkt der letzten Änderung");

        descriptor.Field(u => u.LastModifiedBy)
            .Description("Benutzer, der den Eintrag zuletzt geändert hat");

        descriptor.Field(u => u.TenantId)
            .Description("ID des Tenants, zu dem der Benutzer gehört");

        descriptor.Field(u => u.Roles)
            .Description("Rollen des Benutzers")
            .Type<ListType<UserRoleType>>();

        // Verstecke isDeleted für GraphQL-Clients
        descriptor.Ignore(u => u.IsDeleted);
    }
}