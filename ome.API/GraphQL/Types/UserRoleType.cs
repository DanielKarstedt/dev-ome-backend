using ome.Core.Domain.Entities.Users;

namespace ome.API.GraphQL.Types;

/// <summary>
/// GraphQL-Typ für UserRole-Entität
/// </summary>
public class UserRoleType : ObjectType<UserRole>
{
    protected override void Configure(IObjectTypeDescriptor<UserRole> descriptor)
    {
        descriptor.Description("Repräsentiert eine Rolle eines Benutzers");
            
        descriptor.Field(r => r.Id)
            .Description("Die eindeutige ID der Rolle");
                
        descriptor.Field(r => r.UserId)
            .Description("Die ID des Benutzers");
                
        descriptor.Field(r => r.RoleName)
            .Description("Der Name der Rolle");
                
        descriptor.Field(r => r.TenantId)
            .Description("ID des Tenants, zu dem die Rolle gehört");
                
        // Verstecke isDeleted für GraphQL-Clients
        descriptor.Ignore(r => r.IsDeleted);
    }
}