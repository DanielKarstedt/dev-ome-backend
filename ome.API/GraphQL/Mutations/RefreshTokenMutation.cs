using ome.Core.Interfaces.Services;
namespace ome.API.GraphQL.Mutations;

[ExtendObjectType(typeof(Mutation))]
public class RefreshTokenMutation
{
    [GraphQLDescription("Erneuert ein Access-Token mithilfe eines Refresh-Tokens")]
    public async Task<RefreshTokenPayload> RefreshToken(
        [Service] IKeycloakService keycloakService,
        [Service] IHttpContextAccessor httpContextAccessor,
        [Service] ILogger<RefreshTokenMutation> logger,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Mutation: RefreshToken");

        try
        {
            // Refresh-Token aus Cookie holen
            var httpContext = httpContextAccessor.HttpContext ?? 
                throw new GraphQLException("HTTP-Kontext nicht verfügbar");
                
            var refreshToken = httpContext.Request.Cookies["refresh_token"];
            
            if (string.IsNullOrEmpty(refreshToken))
            {
                logger.LogWarning("Refresh token nicht im Cookie gefunden");
                throw new GraphQLException("Refresh token nicht gefunden");
            }

            // Erneuere das Token
            var newAccessToken = await keycloakService.RefreshTokenAsync(refreshToken, cancellationToken);

            // Token-Informationen abrufen
            var tokenInfo = await keycloakService.GetTokenInfoAsync(newAccessToken, cancellationToken);
            
            // Access-Token-Cookie aktualisieren
            httpContext.Response.Cookies.Append("access_token", newAccessToken, new CookieOptions
            {
                HttpOnly = true,
                Secure = httpContext.Request.IsHttps,
                SameSite = SameSiteMode.Lax,
                Expires = tokenInfo.ExpiresAt
            });

            logger.LogInformation("Token erfolgreich erneuert");

            return new RefreshTokenPayload
            {
                Success = true,
                ExpiresIn = (int)(tokenInfo.ExpiresAt - DateTime.UtcNow).TotalSeconds
            };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Token-Erneuerung fehlgeschlagen");
            throw new GraphQLException("Token-Erneuerung fehlgeschlagen. Bitte melden Sie sich erneut an.");
        }
    }
}

public class RefreshTokenPayload
{
    [GraphQLDescription("Gibt an, ob die Token-Erneuerung erfolgreich war")]
    public bool Success { get; set; }

    [GraphQLDescription("Die Gültigkeitsdauer des neuen Access-Tokens in Sekunden")]
    public int ExpiresIn { get; set; }
}