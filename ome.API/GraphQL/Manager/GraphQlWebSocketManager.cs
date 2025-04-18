using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using ome.API.GraphQL.Interfaces;
using ome.Core.Interfaces.Services;

namespace ome.API.GraphQL.Manager;

/// <summary>
/// Implementierung des GraphQL-WebSocket-Managers
/// </summary>
public class GraphQlWebSocketManager(
    ILogger<GraphQlWebSocketManager> logger,
    IKeycloakService keycloakService)
    : IGraphQlWebSocketManager {

    // Threadsichere Verbindungsspeicherung
    private readonly ConcurrentDictionary<string, GraphQlWebSocketConnection> _connections
        = new ConcurrentDictionary<string, GraphQlWebSocketConnection>();

    public async Task<GraphQlWebSocketConnection> CreateConnectionAsync(string accessToken)
    {
        try
        {
            logger.LogDebug("Erstelle neue GraphQL-WebSocket-Verbindung");
            
            // Token validieren
            var isValid = await keycloakService.ValidateTokenAsync(accessToken);

            if (!isValid)
            {
                logger.LogWarning("Token-Validierung fehlgeschlagen");
                throw new UnauthorizedAccessException("Ungültiger Authentifizierungstoken");
            }

            // Token parsen und ClaimsPrincipal erstellen
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(accessToken);
            var identity = new ClaimsIdentity(token.Claims, "Bearer");
            var claimsPrincipal = new ClaimsPrincipal(identity);

            // Claims sorgfältig extrahieren
            var userId = token.Claims
                .FirstOrDefault(c => c.Type == "sub")?.Value
                ?? token.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)?.Value;
                
            if (string.IsNullOrEmpty(userId))
            {
                logger.LogWarning("Keine Benutzer-ID im Token gefunden");
                throw new UnauthorizedAccessException("Keine Benutzer-ID im Token gefunden");
            }

            // Verschiedene mögliche Claim-Typen für die Firmen-ID überprüfen
            var companyId = token.Claims.FirstOrDefault(c => c.Type == "company")?.Value
                         ?? token.Claims.FirstOrDefault(c => c.Type == "groups")?.Value
                         ?? token.Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value
                         ?? token.Claims.FirstOrDefault(c => c.Type == "tenantId")?.Value;

            if (string.IsNullOrEmpty(companyId))
            {
                logger.LogWarning("Keine Firmen-ID im Token gefunden");
                throw new UnauthorizedAccessException("Keine Firmen-ID im Token gefunden");
            }

            // Falls die Firmen-ID im Pfad-Format vorliegt, extrahiere die ID
            if (companyId.Contains('/'))
            {
                companyId = companyId.Split("/").LastOrDefault() ?? companyId;
            }

            logger.LogInformation("Erstelle Verbindung für Benutzer {UserId}, Firma {CompanyId}", userId, companyId);

            // Verbindung erstellen mit eindeutiger ID
            var connectionId = Guid.NewGuid().ToString();
            var connection = new GraphQlWebSocketConnection
            {
                ConnectionId = connectionId,
                UserClaims = claimsPrincipal,
                CompanyId = companyId,
                ConnectionEstablishedAt = DateTime.UtcNow,
                Metadata = new Dictionary<string, object>
                {
                    ["tokenType"] = "Bearer",
                    ["authMethod"] = "keycloak"
                }
            };

            // Verbindung speichern
            if (_connections.TryAdd(connectionId, connection))
            {
                logger.LogInformation(
                    "GraphQL-WebSocket-Verbindung erstellt: {ConnectionId} für Benutzer {UserId}, Firma {CompanyId}",
                    connectionId, userId, companyId
                );
                return connection;
            }
            else
            {
                logger.LogWarning("Konnte Verbindung nicht in Dictionary speichern");
                throw new InvalidOperationException("Konnte Verbindung nicht registrieren");
            }
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Fehler beim Erstellen der WebSocket-Verbindung");
            throw;
        }
    }

    public IEnumerable<GraphQlWebSocketConnection> GetUserConnections(string userId)
    {
        return _connections.Values
            .Where(c => c.UserClaims.Claims.FirstOrDefault(claim =>
                claim.Type is "sub" or ClaimTypes.NameIdentifier)?.Value == userId);
    }

    public GraphQlWebSocketConnection? GetConnection(string connectionId)
    {
        _connections.TryGetValue(connectionId, out var connection);
        return connection;
    }

    public void RemoveConnection(string connectionId)
    {
        if (_connections.TryRemove(connectionId, out _))
        {
            logger.LogInformation(
                "GraphQL-WebSocket-Verbindung entfernt: {ConnectionId}",
                connectionId
            );
        }
    }

    public IEnumerable<GraphQlWebSocketConnection> GetCompanyConnections(string companyId)
    {
        return _connections.Values
            .Where(c => c.CompanyId == companyId);
    }

    private Task<bool> ValidateToken(string accessToken)
    {
        try
        {
            // Nutze den Keycloak-Service zur Token-Validierung
            return keycloakService.ValidateTokenAsync(accessToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Token-Validierung fehlgeschlagen");
            throw new UnauthorizedAccessException("Ungültiger Authentifizierungstoken");
        }
    }
}