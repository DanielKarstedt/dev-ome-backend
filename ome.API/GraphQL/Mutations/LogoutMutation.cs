using ome.Core.Interfaces.Services;

namespace ome.API.GraphQL.Mutations;

[ExtendObjectType("Mutation")]
public class LogoutMutation {
    [GraphQLDescription("Meldet einen Benutzer ab")]
    public async Task<LogoutPayload> Logout(
        [Service] IKeycloakService keycloakService,
        [Service] IHttpContextAccessor httpContextAccessor,
        [Service] ILogger<LogoutMutation> logger,
        CancellationToken cancellationToken) {
        logger.LogInformation("Mutation: Logout");

        try
        {
            // Refresh-Token aus Cookie holen
            var httpContext = httpContextAccessor.HttpContext ??
                              throw new GraphQLException("HTTP-Kontext nicht verfügbar");

            var refreshToken = httpContext.Request.Cookies["refresh_token"];

            if (string.IsNullOrEmpty(refreshToken))
            {
                logger.LogWarning("Refresh token nicht im Cookie gefunden");
                return new LogoutPayload { Success = false };
            }

            // Führe Logout gegen Keycloak durch
            await keycloakService.LogoutAsync(refreshToken, cancellationToken);

            // Cookies entfernen
            foreach (var cookieName in new[] { "access_token", "refresh_token", "tenant_id" })
            {
                httpContext.Response.Cookies.Delete(cookieName);
            }

            logger.LogInformation("Logout erfolgreich");

            return new LogoutPayload { Success = true };
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Logout fehlgeschlagen");

            // Versuche trotzdem, die Cookies zu löschen
            var httpContext = httpContextAccessor.HttpContext;

            if (httpContext != null)
            {
                foreach (var cookieName in new[] { "access_token", "refresh_token", "tenant_id" })
                {
                    httpContext.Response.Cookies.Delete(cookieName);
                }
            }

            throw new GraphQLException("Logout fehlgeschlagen. Bitte versuchen Sie es später erneut.");
        }
    }
}

public class LogoutPayload {
    [GraphQLDescription("Gibt an, ob die Abmeldung erfolgreich war")]
    public bool Success { get; set; }
}