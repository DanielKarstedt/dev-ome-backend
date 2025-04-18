using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Identity.Services;

/// <summary>
/// Service zum Zugriff auf Informationen des aktuell authentifizierten Benutzers
/// </summary>
public class CurrentUserService(
    IHttpContextAccessor httpContextAccessor,
    ITenantService tenantService,
    ILogger<CurrentUserService> logger)
    : ICurrentUserService {
    private readonly ILogger<CurrentUserService> _logger = logger;
    private readonly JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();
    
    // Private Felder zum Zwischenspeichern von Werten, die manuell gesetzt wurden
    private string? _userId;
    private readonly List<string> _manualRoles = new();

    /// <summary>
    /// Gibt die ID des aktuellen Benutzers zurück
    /// </summary>
    public string UserId => _userId ?? GetClaimValue(ClaimTypes.NameIdentifier);

    /// <summary>
    /// Gibt den Benutzernamen des aktuellen Benutzers zurück
    /// </summary>
    public string Username => GetClaimValue(ClaimTypes.Name);

    /// <summary>
    /// Gibt die E-Mail-Adresse des aktuellen Benutzers zurück
    /// </summary>
    public string Email => GetClaimValue(ClaimTypes.Email);

    /// <summary>
    /// Gibt die ID des aktuellen Tenants zurück
    /// </summary>
    public Guid TenantId => tenantService.GetCurrentTenantId();

    /// <summary>
    /// Gibt an, ob der aktuelle Benutzer authentifiziert ist
    /// </summary>
    public bool IsAuthenticated => (httpContextAccessor.HttpContext?.User.Identity?.IsAuthenticated ?? false) || !string.IsNullOrEmpty(_userId);

    /// <summary>
    /// Gibt die Rollen des aktuellen Benutzers zurück
    /// </summary>
    public IReadOnlyList<string> Roles {
        get {
            if (!IsAuthenticated)
                return Array.Empty<string>();

            var httpContextRoles = httpContextAccessor.HttpContext?.User.Claims
                .Where(c => c.Type == ClaimTypes.Role)
                .Select(c => c.Value)
                .ToList() ?? new List<string>();

            // Kombiniere manuelle Rollen mit Rollen aus Claims
            return httpContextRoles.Concat(_manualRoles).Distinct().ToList();
        }
    }

    /// <summary>
    /// Prüft, ob der aktuelle Benutzer eine bestimmte Rolle hat
    /// </summary>
    public bool IsInRole(string role) {
        return IsAuthenticated && 
               (httpContextAccessor.HttpContext?.User.IsInRole(role) ?? _manualRoles.Contains(role));
    }

    /// <summary>
    /// Setzt die ID des aktuellen Benutzers
    /// </summary>
    public void SetUserId(string userId) {
        _logger.LogDebug("Setze Benutzer-ID auf {UserId}", userId);
        _userId = userId;
    }

    /// <summary>
    /// Fügt eine Rolle für den aktuellen Benutzer hinzu
    /// </summary>
    public void AddRole(string role) {
        _logger.LogDebug("Füge Rolle {Role} für Benutzer {UserId} hinzu", role, UserId);
        if (!_manualRoles.Contains(role)) {
            _manualRoles.Add(role);
        }
    }

    /// <summary>
    /// Extrahiert den Wert eines Claims aus dem Token des aktuellen Benutzers
    /// </summary>
    private string GetClaimValue(string claimType) {
        if (!IsAuthenticated)
            return null!;

        return httpContextAccessor.HttpContext?.User.Claims
            .FirstOrDefault(c => c.Type == claimType)?.Value!;
    }

    /// <summary>
    /// Extrahiert das JWT-Token aus dem Authorization-Header
    /// </summary>
    public string GetJwtToken() {
        var authHeader = httpContextAccessor.HttpContext?.Request.Headers["Authorization"].ToString();

        if (string.IsNullOrEmpty(authHeader) || !authHeader.StartsWith("Bearer "))
            return null!;

        return authHeader["Bearer ".Length..].Trim();
    }
}