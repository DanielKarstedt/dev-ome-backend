using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ome.Core.Features.Auth;

/// <summary>
/// Modul für Authentifizierung und Autorisierung
/// </summary>
public class AuthModule : ModuleBase {
    public override string Name => "Auth";
    public override string Description => "Authentifizierung und Autorisierung mit Keycloak";
    public override string Version => "1.0.0";

    public override void RegisterServices(IServiceCollection services, IConfiguration configuration) {
        if (!IsEnabled)
            return;

        // Registriere Auth-spezifische Services
        // z.B. MediatR Handler für Login, Logout, etc.
    }
}