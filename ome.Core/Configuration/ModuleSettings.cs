namespace ome.Core.Configuration;

/// <summary>
/// Konfigurationsklasse für Modul-Einstellungen
/// </summary>
public class ModuleSettings {
    public Dictionary<string, ModuleConfig> Modules { get; set; } = new Dictionary<string, ModuleConfig>();
}

/// <summary>
/// Konfiguration für ein einzelnes Modul
/// </summary>
public class ModuleConfig {
    /// <summary>
    /// Gibt an, ob das Modul aktiviert ist
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Gibt an, ob das Modul kostenpflichtig ist
    /// </summary>
    public bool IsPremium { get; set; } = false;

    /// <summary>
    /// Spezifische Konfigurationseinstellungen für das Modul
    /// </summary>
    public Dictionary<string, string> Settings { get; set; } = new Dictionary<string, string>();
}