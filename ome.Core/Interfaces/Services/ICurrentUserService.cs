namespace ome.Core.Interfaces.Services;

/// <summary>
/// Interface für den Service zum Zugriff auf Informationen des aktuellen Benutzers
/// </summary>
public interface ICurrentUserService
{
    /// <summary>
    /// Gibt die ID des aktuellen Benutzers zurück
    /// </summary>
    string UserId { get; }
    
    /// <summary>
    /// Gibt den Benutzernamen des aktuellen Benutzers zurück
    /// </summary>
    string Username { get; }
    
    /// <summary>
    /// Gibt die E-Mail-Adresse des aktuellen Benutzers zurück
    /// </summary>
    string Email { get; }
    
    /// <summary>
    /// Gibt die ID des aktuellen Tenants zurück
    /// </summary>
    Guid TenantId { get; }
    
    /// <summary>
    /// Gibt an, ob der aktuelle Benutzer authentifiziert ist
    /// </summary>
    bool IsAuthenticated { get; }
    
    /// <summary>
    /// Gibt die Rollen des aktuellen Benutzers zurück
    /// </summary>
    IReadOnlyList<string> Roles { get; }
    
    /// <summary>
    /// Prüft, ob der aktuelle Benutzer eine bestimmte Rolle hat
    /// </summary>
    bool IsInRole(string role);
    
    /// <summary>
    /// Extrahiert das JWT-Token aus dem Authorization-Header
    /// </summary>
    string GetJwtToken();
    
    /// <summary>
    /// Setzt die ID des aktuellen Benutzers
    /// </summary>
    void SetUserId(string userId);
    
    /// <summary>
    /// Fügt eine Rolle für den aktuellen Benutzer hinzu
    /// </summary>
    void AddRole(string role);
}