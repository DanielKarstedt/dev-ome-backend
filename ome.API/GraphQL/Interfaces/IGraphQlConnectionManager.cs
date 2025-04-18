using System.Security.Claims;

namespace ome.API.GraphQL.Interfaces;

/// <summary>
/// Represents the parameters for establishing an authenticated GraphQL connection
/// </summary>
public class GraphQlConnectionParams
{
    /// <summary>
    /// Unique identifier for the user
    /// </summary>
    public string UserId { get; set; } = null!;

    /// <summary>
    /// Company/Tenant identifier
    /// </summary>
    public string CompanyId { get; set; } = null!;

    /// <summary>
    /// JWT Access Token for authentication
    /// </summary>
    public string AccessToken { get; set; } = null!;

    /// <summary>
    /// Refresh Token for maintaining long-lived sessions
    /// </summary>
    public string RefreshToken { get; set; } = null!;
}

/// <summary>
/// Represents an authenticated GraphQL connection
/// </summary>
public class GraphQlConnection
{
    /// <summary>
    /// Unique connection identifier
    /// </summary>
    public string ConnectionId { get; set; } = null!;

    /// <summary>
    /// User claims extracted from the access token
    /// </summary>
    public ClaimsPrincipal UserClaims { get; set; } = null!;

    /// <summary>
    /// Current access token
    /// </summary>
    public string CurrentAccessToken { get; set; } = null!;

    /// <summary>
    /// Current refresh token
    /// </summary>
    public string CurrentRefreshToken { get; init; } = null!;

    /// <summary>
    /// Timestamp when the connection was established
    /// </summary>
    public DateTime ConnectionEstablishedAt { get; set; }

    /// <summary>
    /// Indicates if the connection is still active
    /// </summary>
    public bool IsActive { get; init; }

    /// <summary>
    /// Add Metadata to the connection
    /// </summary>
    public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();
}

/// <summary>
/// Manages GraphQL connections (both HTTP and WebSocket)
/// </summary>
public interface IGraphQlConnectionManager
{
    /// <summary>
    /// Create an authenticated GraphQL connection
    /// </summary>
    /// <param name="parameters">Connection authentication parameters</param>
    /// <returns>Authenticated GraphQL connection</returns>
    Task<GraphQlConnection> CreateAuthenticatedConnectionAsync(GraphQlConnectionParams parameters);

    /// <summary>
    /// Get an existing GraphQL connection by connection ID
    /// </summary>
    /// <param name="connectionId">Unique connection identifier</param>
    /// <returns>GraphQL connection or null if not found</returns>
    GraphQlConnection? GetConnection(string connectionId);

    /// <summary>
    /// Remove a GraphQL connection
    /// </summary>
    /// <param name="connectionId">Unique connection identifier</param>
    void RemoveConnection(string connectionId);

    /// <summary>
    /// Get all active connections for a specific user
    /// </summary>
    /// <param name="userId">User identifier</param>
    /// <returns>Collection of active GraphQL connections</returns>
    IEnumerable<GraphQlConnection> GetUserConnections(string userId);

    /// <summary>
    /// Get all active connections for a specific company
    /// </summary>
    /// <param name="companyId">Company identifier</param>
    /// <returns>Collection of active GraphQL connections</returns>
    IEnumerable<GraphQlConnection> GetCompanyConnections(string companyId);

    /// <summary>
    /// Refresh the access token for a given connection
    /// </summary>
    /// <param name="connectionId">Unique connection identifier</param>
    /// <returns>New access token</returns>
    Task<string> RefreshConnectionTokenAsync(string connectionId);

    /// <summary>
    /// Validate and decode the access token
    /// </summary>
    /// <param name="accessToken">JWT Access Token</param>
    /// <returns>Claims principal if token is valid</returns>
    ClaimsPrincipal ValidateAccessToken(string accessToken);

    /// <summary>
    /// Check if a connection is still valid
    /// </summary>
    /// <param name="connectionId">Unique connection identifier</param>
    /// <returns>True if connection is valid, false otherwise</returns>
    bool IsConnectionValid(string connectionId);
}

/// <summary>
/// Represents different types of GraphQL connections
/// </summary>
public enum GraphQlConnectionType
{
    /// <summary>
    /// Standard HTTP GraphQL endpoint
    /// </summary>
    Http,

    /// <summary>
    /// WebSocket-based GraphQL subscriptions
    /// </summary>
    WebSocket
}