using System.Security.Claims;
using ome.Core.Interfaces.Services;

namespace ome.API.GraphQL.Middlewares;

public class GraphQlAuthMiddleware {
    private readonly RequestDelegate _next;
    private readonly ILogger<GraphQlAuthMiddleware> _logger;

    public GraphQlAuthMiddleware(
        RequestDelegate next,
        ILogger<GraphQlAuthMiddleware> logger) {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(
        HttpContext context,
        IKeycloakService keycloakService,
        ITenantService tenantService,
        ICurrentUserService currentUserService) {
        // GraphQL-Endpoint-Pfad (aus Konfiguration oder Konstante)
        const string graphQlPath = "/graphql";

        // Nur für GraphQL-Pfad ausführen
        if (!context.Request.Path.StartsWithSegments(graphQlPath))
        {
            await _next(context);
            return;
        }

        _logger.LogDebug("GraphQL-Anfrage erkannt");

        // Token aus Cookies holen (alle sind HttpOnly)
        var accessToken = context.Request.Cookies["access_token"];

        if (string.IsNullOrEmpty(accessToken))
        {
            _logger.LogDebug("Kein Access-Token für GraphQL-Anfrage gefunden");
            await _next(context);
            return;
        }

        try
        {
            // Validiere das Token
            var isValid = await keycloakService.ValidateTokenAsync(accessToken);

            if (!isValid)
            {
                _logger.LogWarning("Ungültiges Token für GraphQL-Anfrage");

                // Token automatisch aktualisieren, wenn möglich
                var refreshToken = context.Request.Cookies["refresh_token"];

                if (!string.IsNullOrEmpty(refreshToken))
                {
                    try
                    {
                        _logger.LogInformation("Versuche, Token zu erneuern");

                        var newAccessToken = await keycloakService.RefreshTokenAsync(refreshToken);
                        var tokenInfo = await keycloakService.GetTokenInfoAsync(newAccessToken);

                        // Cookie aktualisieren
                        context.Response.Cookies.Append("access_token", newAccessToken, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = context.Request.IsHttps,
                            SameSite = SameSiteMode.Lax,
                            Expires = tokenInfo.ExpiresAt
                        });

                        // Neues Token verwenden
                        accessToken = newAccessToken;
                        isValid = true;

                        _logger.LogInformation("Token erfolgreich erneuert");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Fehler beim Erneuern des Tokens");
                    }
                }

                if (!isValid)
                {
                    await _next(context);
                    return;
                }
            }

            // Token-Informationen abrufen
            var info = await keycloakService.GetTokenInfoAsync(accessToken);

            // Tenant-ID setzen
            if (!string.IsNullOrEmpty(info.TenantId) && Guid.TryParse(info.TenantId, out var tenantId))
            {
                tenantService.SetCurrentTenantId(tenantId);
            }

            // Benutzer-ID und Rollen setzen
            if (!string.IsNullOrEmpty(info.UserId))
            {
                currentUserService.SetUserId(info.UserId);

                foreach (var role in info.Roles)
                {
                    currentUserService.AddRole(role);
                }
            }

            // Claims erstellen und Benutzer authentifizieren
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, info.UserId ?? string.Empty),
                new Claim(ClaimTypes.Name, info.Username ?? string.Empty),
                new Claim(ClaimTypes.Email, info.Email ?? string.Empty)
            };
            claims.AddRange(info.Roles.Select(role => new Claim(ClaimTypes.Role, role)));

            var identity = new ClaimsIdentity(claims, "Token");
            context.User = new ClaimsPrincipal(identity);

            // Wichtig: Füge den Bearer-Token als Authorization-Header hinzu,
            // da GraphQL diesen benötigt und nicht auf HttpOnly-Cookies zugreifen kann
            context.Request.Headers.Authorization = $"Bearer {accessToken}";

            _logger.LogDebug("Benutzer für GraphQL authentifiziert: {Username}", info.Username);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Fehler bei der GraphQL-Authentifizierung");
        }

        await _next(context);
    }
}