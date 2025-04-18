using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ome.Core.Features.Users;

/// <summary>
/// Modul für Benutzerverwaltung
/// </summary>
public class UsersModule: ModuleBase {
    public override string Name => "Users";
    public override string Description => "Benutzerverwaltung";
    public override string Version => "1.0.0";

    public override void RegisterServices(IServiceCollection services, IConfiguration configuration) {
        if (!IsEnabled)
            return;

        // Registriere User-spezifische Services
        // z.B. MediatR Handler für CreateUser, UpdateUser, DeleteUser
    }
}