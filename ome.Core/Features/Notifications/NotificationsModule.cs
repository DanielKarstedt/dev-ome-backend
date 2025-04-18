using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ome.Core.Features.Notifications;

/// <summary>
/// Modul für Benachrichtigungen
/// </summary>
public class NotificationsModule: ModuleBase {
    public override string Name => "Notifications";
    public override string Description => "Benachrichtigungen für Benutzeraktionen";
    public override string Version => "1.0.0";

    public override void RegisterServices(IServiceCollection services, IConfiguration configuration) {
        if (!IsEnabled)
            return;

        // Registriere Notification-spezifische Services
        // z.B. MediatR Handler für Notification Events
    }
}