using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using ome.API.GraphQL.Interfaces;
using ome.Core.Interfaces.Services;
using KeyNotFoundException = GreenDonut.KeyNotFoundException;

namespace ome.API.GraphQL.Manager;

/// <summary>
/// Implementierung des GraphQL-Verbindungsmanagers
/// </summary>
public class GraphQlConnectionManager(
    ILogger<GraphQlConnectionManager> logger,
    IKeycloakService keycloakService)
    : IGraphQlConnectionManager {
    private readonly ConcurrentDictionary<string, GraphQlConnection> _connections =
        new ConcurrentDictionary<string, GraphQlConnection>();

    public Task<GraphQlConnection> CreateAuthenticatedConnectionAsync(GraphQlConnectionParams parameters) {
        // Prüfen, ob alle erforderlichen Parameter vorhanden sind
        ArgumentNullException.ThrowIfNull(parameters);
        ArgumentException.ThrowIfNullOrEmpty(parameters.UserId);
        ArgumentException.ThrowIfNullOrEmpty(parameters.CompanyId);
        ArgumentException.ThrowIfNullOrEmpty(parameters.AccessToken);

        try {
            // Token validieren
            var tokenClaims = ValidateAccessToken(parameters.AccessToken);

            // Rollen extrahieren
            var roles = tokenClaims.Claims
                .Where(c => c.Type == "roles" || c.Type == "role")
                .Select(c => c.Value)
                .ToList();

            // Verbindung erstellen
            var connection = new GraphQlConnection {
                ConnectionId = Guid.NewGuid().ToString(),
                UserClaims = tokenClaims,
                CurrentAccessToken = parameters.AccessToken,
                CurrentRefreshToken = parameters.RefreshToken,
                ConnectionEstablishedAt = DateTime.UtcNow,
                IsActive = true,
                Metadata = new Dictionary<string, object> {
                    ["UserId"] = parameters.UserId,
                    ["CompanyId"] = parameters.CompanyId,
                    ["Roles"] = roles 
                }
            };

            // Verbindung speichern
            _connections[connection.ConnectionId] = connection;

            logger.LogInformation(
                "GraphQL-Verbindung erstellt: {ConnectionId} für Benutzer {UserId}, Firma {CompanyId}, Rollen: {Roles}",
                connection.ConnectionId,
                parameters.UserId,
                parameters.CompanyId,
                string.Join(", ", roles)
            );

            return Task.FromResult(connection);
        }
        catch (Exception ex) {
            logger.LogError(ex, "Fehler beim Erstellen der GraphQL-Verbindung");
            throw;
        }
    }

    public GraphQlConnection? GetConnection(string connectionId) {
        _connections.TryGetValue(connectionId, out var connection);
        return connection;
    }

    public void RemoveConnection(string connectionId) {
        if (_connections.TryRemove(connectionId, out _)) {
            logger.LogInformation(
                "GraphQL-Verbindung entfernt: {ConnectionId}",
                connectionId
            );
        }
    }

    public IEnumerable<GraphQlConnection> GetUserConnections(string userId) {
        return _connections.Values
            .Where(c => c.UserClaims.Claims.FirstOrDefault(claim =>
                claim.Type == ClaimTypes.NameIdentifier)?.Value == userId);
    }

    public IEnumerable<GraphQlConnection> GetCompanyConnections(string companyId) {
        return _connections.Values
            .Where(c => c.UserClaims.Claims.FirstOrDefault(claim =>
                claim.Type == "company")?.Value == companyId);
    }

    public async Task<string> RefreshConnectionTokenAsync(string connectionId) {
        if (!_connections.TryGetValue(connectionId, out var connection))
            throw new KeyNotFoundException($"Verbindung mit ID {connectionId} nicht gefunden");

        try {
            // Refresh-Token verwenden, um einen neuen Access-Token zu erhalten
            var newAccessToken = await keycloakService.RefreshTokenAsync(connection.CurrentRefreshToken);

            // Verbindung aktualisieren
            connection.CurrentAccessToken = newAccessToken;
            // Der RefreshToken bleibt unverändert, da er vom Service nicht zurückgegeben wird

            return newAccessToken;
        }
        catch (Exception ex) {
            logger.LogError(ex, "Fehler beim Aktualisieren des Tokens für Verbindung {ConnectionId}", connectionId);
            throw;
        }
    }

    public ClaimsPrincipal ValidateAccessToken(string accessToken) {
        try {
            // Token validieren (vereinfachte Implementierung)
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(accessToken);
            var identity = new ClaimsIdentity(token.Claims, "Bearer");
            return new ClaimsPrincipal(identity);

            // In einer vollständigen Implementierung sollte hier eine echte Validierung erfolgen
            // Die könnte beispielsweise über den Keycloak-Service geschehen
        }
        catch (Exception ex) {
            logger.LogError(ex, "Token-Validierung fehlgeschlagen");
            throw new UnauthorizedAccessException("Ungültiger Authentifizierungstoken");
        }
    }

    public bool IsConnectionValid(string connectionId) {
        if (!_connections.TryGetValue(connectionId, out var connection))
            return false;

        // Prüfen, ob die Verbindung noch aktiv ist und der Token noch gültig ist
        if (!connection.IsActive)
            return false;

        try {
            // Token aus der Verbindung prüfen
            var handler = new JwtSecurityTokenHandler();
            var token = handler.ReadJwtToken(connection.CurrentAccessToken);

            // Prüfen, ob der Token abgelaufen ist
            return token.ValidTo > DateTime.UtcNow;
        }
        catch {
            return false;
        }
    }
}