using System.Security.Claims;

namespace ome.API.GraphQL.Interfaces;

/// <summary>
/// Repräsentiert eine GraphQL-WebSocket-Verbindung
/// </summary>
public class GraphQlWebSocketConnection 
{
    /// <summary>
    /// Eindeutige Verbindungs-ID
    /// </summary>
    public string ConnectionId { get; set; } = Guid.NewGuid().ToString();

    /// <summary>
    /// Benutzer-Claims aus dem Authentifizierungstoken
    /// </summary>
    public ClaimsPrincipal UserClaims { get; init; } = null!;

    /// <summary>
    /// Zeitpunkt der Verbindungsherstellung
    /// </summary>
    public DateTime ConnectionEstablishedAt { get; set; } = DateTime.UtcNow;

    /// <summary>
    /// Unternehmen/Mandant der Verbindung
    /// </summary>
    public string CompanyId { get; init; } = null!;

    /// <summary>
    /// Zusätzliche Verbindungsmetadaten
    /// </summary>
    public Dictionary<string, object> Metadata { get; init; } = new Dictionary<string, object>();
}

/// <summary>
/// Interface für den GraphQL-WebSocket-Manager
/// </summary>
public interface IGraphQlWebSocketManager 
{
    /// <summary>
    /// Authentifiziert und registriert eine neue GraphQL-WebSocket-Verbindung
    /// </summary>
    Task<GraphQlWebSocketConnection> CreateConnectionAsync(string accessToken);

    /// <summary>
    /// Holt eine bestehende Verbindung
    /// </summary>
    GraphQlWebSocketConnection? GetConnection(string connectionId);

    /// <summary>
    /// Entfernt eine Verbindung
    /// </summary>
    void RemoveConnection(string connectionId);

    /// <summary>
    /// Listet alle Verbindungen für einen Benutzer
    /// </summary>
    IEnumerable<GraphQlWebSocketConnection> GetUserConnections(string userId);

    /// <summary>
    /// Listet alle Verbindungen für ein Unternehmen
    /// </summary>
    IEnumerable<GraphQlWebSocketConnection> GetCompanyConnections(string companyId);
}