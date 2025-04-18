namespace ome.Core.Interfaces.Services;

/// <summary>
/// Interface für den Keycloak-Service
/// </summary>
public interface IKeycloakService {
    /// <summary>
    /// Generiert die Autorisierungs-URL für den OAuth-Flow
    /// </summary>
    string GetAuthorizationUrl(string redirectUri, string state);

    /// <summary>
    /// Tauscht den Autorisierungscode gegen Tokens aus
    /// </summary>
    Task<(string AccessToken, string RefreshToken)> ExchangeCodeForTokenAsync(
        string code,
        string redirectUri,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Erneuert ein Token mithilfe eines Refresh-Tokens
    /// </summary>
    Task<string> RefreshTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Führt den Logout-Vorgang durch
    /// </summary>
    Task LogoutAsync(
        string refreshToken,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Validiert ein Token
    /// </summary>
    Task<bool> ValidateTokenAsync(string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Extrahiert die TenantId aus einem Token
    /// </summary>
    Task<Guid> GetTenantIdFromTokenAsync(
        string token,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Extrahiert Informationen aus einem Token
    /// </summary>
    Task<TokenInfo> GetTokenInfoAsync(
        string token,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Informationen zu einem Token
/// </summary>
public class TokenInfo {
    public string? UserId { get; init; }
    public string? Username { get; init; }
    public string? Email { get; init; }
    public string? TenantId { get; init; }
    public DateTime ExpiresAt { get; init; }
    public List<string> Roles { get; init; } = [];
}