using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace ome.Core;

/// <summary>
/// Basis-Klasse für Feature-Module
/// </summary>
public class ModuleBase {
    /// <summary>
    /// Name des Moduls
    /// </summary>
    public virtual string Name { get; } = null!;

    /// <summary>
    /// Beschreibung des Moduls
    /// </summary>
    public virtual string Description { get; } = null!;

    /// <summary>
    /// Version des Moduls
    /// </summary>
    public virtual string Version { get; } = null!;

    /// <summary>
    /// Gibt an, ob das Modul aktiviert ist
    /// </summary>
    public virtual bool IsEnabled { get; private set; } = true;

    /// <summary>
    /// Initialisiert das Modul mit der Konfiguration
    /// </summary>
    public virtual void Initialize(IConfiguration configuration) {
        var section = configuration.GetSection("Modules:" + Name);
        IsEnabled = !bool.TryParse(section["Enabled"], out var enabled) || enabled;
    }

    /// <summary>
    /// Registriert die Module-Dienste im Dependency Injection Container
    /// </summary>
    public virtual void RegisterServices(IServiceCollection services, IConfiguration configuration) {
        throw new NotImplementedException();
    }
}