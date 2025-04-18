using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using ome.Core;

namespace ome.Infrastructure.Modules;

/// <summary>
/// Manager für die Verwaltung von Feature-Modulen
/// </summary>
public class ModuleManager {
    private readonly List<ModuleBase> _modules = [];

    /// <summary>
    /// Registriert ein Modul (aktiviert oder deaktiviert)
    /// </summary>
    public void RegisterModule(ModuleBase module, bool isEnabled = true) {
        if (!isEnabled)
        {
            // Setze das Modul auf deaktiviert
            typeof(ModuleBase).GetProperty("IsEnabled")?.SetValue(module, false);
        }

        _modules.Add(module);
    }

    /// <summary>
    /// Gibt alle registrierten Module zurück
    /// </summary>
    public IReadOnlyList<ModuleBase> GetModules() {
        return _modules.AsReadOnly();
    }

    /// <summary>
    /// Gibt alle aktivierten Module zurück
    /// </summary>
    public IReadOnlyList<ModuleBase> GetEnabledModules() {
        return _modules.Where(m => m.IsEnabled).ToList().AsReadOnly();
    }

    /// <summary>
    /// Konfiguriert die Services aller aktivierten Module
    /// </summary>
    public void ConfigureServices(IServiceCollection services, IConfiguration configuration) {
        foreach (var module in _modules.Where(m => m.IsEnabled))
        {
            // Initialisiere das Modul mit der Konfiguration
            module.Initialize(configuration);

            // Registriere die Services des Moduls
            module.RegisterServices(services, configuration);
        }

        // Registriere den ModuleManager im DI-Container
        services.AddSingleton(this);
    }
}