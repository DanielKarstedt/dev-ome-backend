using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using System.Web;
using HotChocolate.Authorization;
using Microsoft.AspNetCore.Authentication;
using ome.API.GraphQL.Interfaces;
using ome.Core.Interfaces.Services;

namespace ome.API.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(
    IKeycloakService keycloakService,
    ITenantService tenantService,
    IGraphQlWebSocketManager webSocketManager,
    IGraphQlConnectionManager graphQlManager,
    ILogger<AuthController> logger,
    IConfiguration configuration)
    : ControllerBase {
    /// <summary>
    /// Generiert eine Login-URL für Keycloak-Authentifizierung
    /// </summary>
    /// <param name="redirectUri">Optionale Weiterleitungs-URI nach erfolgreicher Anmeldung</param>
    /// <returns>Weiterleitung zur Keycloak-Login-Seite</returns>
    /// <response code="302">Weiterleitung zur Keycloak-Login-Seite</response>
    /// <response code="500">Fehler bei der Generierung der Login-URL</response>
    [HttpGet("login")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public IActionResult GenerateLoginUrl([FromQuery] string redirectUri = "/dashboard") {
        try {
            logger.LogInformation("Generating Keycloak login URL with redirect: {RedirectUri}", redirectUri);

            // Combine redirectUri + CSRF state in JSON
            var statePayload = new {
                csrf = Guid.NewGuid().ToString(),
                redirect = redirectUri
            };
            var stateJson = JsonSerializer.Serialize(statePayload);

            var encodedState = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(stateJson));

            // Build Auth URL
            var baseUrl = configuration["Keycloak:BaseUrl"];
            var realm = configuration["Keycloak:Realm"];
            var clientId = configuration["Keycloak:ClientId"];

            if (string.IsNullOrEmpty(baseUrl) || string.IsNullOrEmpty(realm) || string.IsNullOrEmpty(clientId)) {
                throw new InvalidOperationException("Keycloak configuration is incomplete");
            }

            // Use the exact callback URL format as in Keycloak client configuration
            const string callbackUrl = "https://api.officemadeeasy.eu/api/Auth/callback";
            logger.LogInformation("Using fixed callback URL: {CallbackUrl}", callbackUrl);

            var authUrl = $"{baseUrl}/realms/{realm}/protocol/openid-connect/auth" +
                          $"?response_type=code" +
                          $"&client_id={HttpUtility.UrlEncode(clientId)}" +
                          $"&redirect_uri={HttpUtility.UrlEncode(callbackUrl)}" +
                          $"&state={HttpUtility.UrlEncode(encodedState)}" +
                          $"&scope=openid%20profile%20email";

            // Redirect directly to Keycloak
            logger.LogInformation("Redirecting to Keycloak auth URL: {AuthUrl}", authUrl);
            return Redirect(authUrl);
        }
        catch (Exception ex) {
            logger.LogError(ex, "Failed to generate login URL: {ErrorMessage}", ex.Message);
            return StatusCode(500, new ErrorResponse { Message = $"Failed to generate login URL: {ex.Message}" });
        }
    }

    /// <summary>
    /// Verarbeitet OAuth-Callback von Keycloak nach erfolgreicher Authentifizierung
    /// </summary>
    /// <param name="code">Autorisierungscode von Keycloak</param>
    /// <param name="state">State-Parameter für CSRF-Schutz</param>
    /// <returns>Weiterleitung zum Frontend mit Authentifizierungsinformationen</returns>
    /// <response code="302">Erfolgreiche Authentifizierung, Weiterleitung zum Frontend</response>
    /// <response code="400">Ungültige Anfrageparameter</response>
    /// <response code="500">Fehler bei der Verarbeitung der Authentifizierung</response>
    [HttpGet("callback")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Callback([FromQuery] string code, [FromQuery] string state) {
        try {
            // Validate input parameters
            if (string.IsNullOrWhiteSpace(code)) {
                logger.LogError("Invalid or missing authorization code");
                return BadRequest(new ErrorResponse { Message = "Invalid authorization code" });
            }

            logger.LogInformation("OAuth callback received with state: {State}", state);

            // Decode state parameter and extract original redirect
            var redirectPath = "/dashboard";
            var csrf = "";

            try {
                var decodedState = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(state));
                logger.LogDebug("Decoded State: {DecodedState}", decodedState);

                var stateObj = JsonSerializer.Deserialize<JsonElement>(decodedState);

                if (stateObj.TryGetProperty("redirect", out var redirectProp)) {
                    redirectPath = redirectProp.GetString() ?? "/dashboard";
                }

                if (stateObj.TryGetProperty("csrf", out var csrfProp)) {
                    csrf = csrfProp.GetString() ?? "";
                }

                logger.LogInformation("Extracted Redirect Path: {RedirectPath}, CSRF: {Csrf}", redirectPath, csrf);
            }
            catch (Exception ex) {
                logger.LogWarning(ex, "Could not decode state parameter, using default redirect");
            }

            // Fixed callback URL for token exchange
            const string callbackUrl = "https://api.officemadeeasy.eu/api/Auth/callback";
            logger.LogDebug("Using fixed callback URL for token exchange: {CallbackUrl}", callbackUrl);

            // Attempt token exchange with detailed logging
            var tokenExchangeResult = await AttemptTokenExchangeWithDetailedLogging(code, callbackUrl);

            if (tokenExchangeResult.IsSuccessful) {
                return await ProcessSuccessfulAuthentication(
                    tokenExchangeResult.AccessToken!,
                    tokenExchangeResult.RefreshToken!,
                    redirectPath
                );
            }
            else {
                return HandleAuthenticationFailure(tokenExchangeResult);
            }
        }
        catch (Exception ex) {
            logger.LogError(ex, "Critical authentication callback error");
            return StatusCode(500, new ErrorResponse { Message = "Authentication process failed" });
        }
    }

    /// <summary>
    /// Attempts to exchange authorization code for tokens with detailed logging
    /// </summary>
    private async Task<TokenExchangeResult> AttemptTokenExchangeWithDetailedLogging(string code, string callbackUrl) {
        try {
            logger.LogInformation("Attempting to exchange code for tokens with callback URL: {Url}", callbackUrl);

            var (accessToken, refreshToken) = await keycloakService.ExchangeCodeForTokenAsync(code, callbackUrl);

            if (string.IsNullOrEmpty(accessToken)) {
                logger.LogError("Received empty access token during code exchange");

                return new TokenExchangeResult {
                    IsSuccessful = false,
                    ErrorType = "EmptyToken",
                    ErrorDescription = "Received empty access token"
                };
            }

            logger.LogInformation("Successfully exchanged code for tokens. Access token length: {Length}",
                accessToken.Length);

            return new TokenExchangeResult {
                IsSuccessful = true,
                AccessToken = accessToken,
                RefreshToken = refreshToken
            };
        }
        catch (HttpRequestException httpEx) {
            logger.LogError(httpEx, "HTTP error during token exchange: {ErrorMessage}", httpEx.Message);

            return new TokenExchangeResult {
                IsSuccessful = false,
                ErrorType = "HttpError",
                ErrorDescription = httpEx.Message
            };
        }
        catch (Exception ex) {
            logger.LogError(ex, "Unexpected error during token exchange: {ErrorMessage}", ex.Message);

            return new TokenExchangeResult {
                IsSuccessful = false,
                ErrorType = "UnknownError",
                ErrorDescription = ex.Message
            };
        }
    }

    /// <summary>
    /// Meldet den aktuellen Benutzer ab
    /// </summary>
    /// <returns>Weiterleitung zur Login-Seite</returns>
    /// <response code="302">Erfolgreiche Abmeldung, Weiterleitung zur Login-Seite</response>
    [HttpGet("logout")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [Authorize]
    public async Task<IActionResult> Logout() {
        try {
            logger.LogInformation("Benutzer wird abgemeldet");

            // 1. Cookie-Authentifizierung beenden
            await HttpContext.SignOutAsync("Cookies");

            // 2. Session-Cookies löschen
            foreach (var cookie in Request.Cookies.Keys) {
                Response.Cookies.Delete(cookie);
            }

            // 3. Lokale Verbindungen trennen
            // Hier könnten WebSocket-Verbindungen getrennt werden

            logger.LogInformation("Benutzer erfolgreich abgemeldet");

            // 4. Zur Login-Seite weiterleiten
            var frontendBaseUrl = configuration["Frontend:BaseUrl"] ?? "https://localhost:3000";
            var loginUrl = $"{frontendBaseUrl.TrimEnd('/')}/login";

            logger.LogInformation("Leite zur Login-Seite weiter: {LoginUrl}", loginUrl);
            return Redirect(loginUrl);
        }
        catch (Exception ex) {
            logger.LogError(ex, "Fehler beim Abmelden: {ErrorMessage}", ex.Message);

            // Zur Sicherheit trotzdem zur Login-Seite weiterleiten
            var frontendBaseUrl = configuration["Frontend:BaseUrl"] ?? "https://localhost:3000";
            return Redirect($"{frontendBaseUrl.TrimEnd('/')}/login?error=logout_failed");
        }
    }

    /// <summary>
    /// Prüft, ob der aktuelle Benutzer authentifiziert ist
    /// </summary>
    /// <returns>Status der Authentifizierung</returns>
    /// <response code="200">Erfolgreiche Statusprüfung</response>
    [HttpGet("status")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public IActionResult GetAuthStatus() {
        var isAuthenticated = HttpContext.User.Identity?.IsAuthenticated ?? false;
        var userId = HttpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var username = HttpContext.User.FindFirstValue(ClaimTypes.Name);

        logger.LogInformation("Auth-Status für Benutzer {UserId}: IsAuthenticated={IsAuthenticated}",
            userId ?? "unknown", isAuthenticated);

        return Ok(new {
            IsAuthenticated = isAuthenticated,
            UserId = userId,
            Username = username
        });
    }

    /// <summary>
    /// Handles authentication failure with appropriate logging and redirection
    /// </summary>
    public IActionResult HandleAuthenticationFailure(TokenExchangeResult result) {
        var frontendBaseUrl = configuration["Frontend:BaseUrl"] ?? "https://localhost:3000";
        var errorMessage = result.ErrorType ?? "auth_failed";

        logger.LogWarning("Authentication failed. Redirecting to error page. Error: {ErrorMessage}", errorMessage);

        return Redirect($"{frontendBaseUrl.TrimEnd('/')}/error?message={errorMessage}");
    }

    /// <summary>
    /// Verarbeitet erfolgreiche Authentifizierung nach Token-Exchange
    /// </summary>
    /// <param name="accessToken">Access Token von Keycloak</param>
    /// <param name="refreshToken">Refresh Token von Keycloak</param>
    /// <param name="redirectPath">Pfad für Weiterleitung nach Authentifizierung</param>
    /// <returns>Weiterleitungs-Action</returns>
    private async Task<IActionResult> ProcessSuccessfulAuthentication(
        string accessToken,
        string refreshToken,
        string redirectPath) {
        try {
            logger.LogInformation("Verarbeite erfolgreiche Authentifizierung");

            // JWT Token dekodieren und Claims extrahieren
            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtHandler.ReadJwtToken(accessToken);

            // Extrahiere Benutzer-Identifier
            var userIdentifier = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;
            var username = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value;
            var email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value;

            if (string.IsNullOrEmpty(userIdentifier)) {
                logger.LogWarning("Keine Benutzer-ID (sub) im Token gefunden");

                return HandleAuthenticationFailure(new TokenExchangeResult {
                    IsSuccessful = false,
                    ErrorType = "NoUserId",
                    ErrorDescription = "Benutzer-ID nicht im Token gefunden"
                });
            }

            logger.LogInformation("Benutzer-ID: {UserId}, Username: {Username}, E-Mail: {Email}",
                userIdentifier, username ?? "unbekannt", email ?? "unbekannt");

            // Extrahiere Company ID - unterstützt mehrere Claim-Typen
            var companyId = jwtToken.Claims.FirstOrDefault(c => c.Type == "company")?.Value
                            ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "tenant_id")?.Value;

            // Wenn keine direkte Company-ID gefunden wurde, versuche aus Gruppen zu extrahieren
            if (string.IsNullOrEmpty(companyId)) {
                var groups = jwtToken.Claims.Where(c => c.Type == "groups").Select(c => c.Value).ToList();
                logger.LogInformation("Gefundene Gruppen: {Groups}", string.Join(", ", groups));

                // Suche nach tenant:xxx Gruppe
                var tenantGroup =
                    groups.FirstOrDefault(g => g.StartsWith("tenant:", StringComparison.OrdinalIgnoreCase));

                if (!string.IsNullOrEmpty(tenantGroup)) {
                    companyId = tenantGroup.Split(':').LastOrDefault();
                    logger.LogInformation("Company-ID aus Gruppe extrahiert: {CompanyId}", companyId);
                }
            }

            if (string.IsNullOrEmpty(companyId)) {
                logger.LogWarning("Keine Company-ID für Benutzer gefunden");

                // Alternative: Verwende den Realm-Namen als Fallback (für Single-Tenant-Anwendungen)
                var realmName = jwtToken.Claims.FirstOrDefault(c => c.Type == "azp")?.Value;

                if (!string.IsNullOrEmpty(realmName)) {
                    companyId = realmName;
                    logger.LogInformation("Verwende Realm-Namen als Company-ID: {CompanyId}", companyId);
                }
                else {
                    return HandleAuthenticationFailure(new TokenExchangeResult {
                        IsSuccessful = false,
                        ErrorType = "NoCompanyId",
                        ErrorDescription = "Keine Company-ID im Token gefunden"
                    });
                }
            }

            // Behandle Company-ID im Pfad-Format
            if (companyId.Contains('/')) {
                var originalCompanyId = companyId;
                companyId = companyId.Split("/").LastOrDefault() ?? companyId;

                logger.LogInformation("Company-ID aus Pfad extrahiert: {OriginalId} -> {ExtractedId}",
                    originalCompanyId, companyId);
            }

            // Token-Ablaufzeit extrahieren
            var expiryTimestamp = jwtToken.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
            var expiryDate = DateTimeOffset.UtcNow.AddHours(1); // Default: 1 Stunde

            if (!string.IsNullOrEmpty(expiryTimestamp) && long.TryParse(expiryTimestamp, out var unixTime)) {
                expiryDate = DateTimeOffset.FromUnixTimeSeconds(unixTime);
                logger.LogInformation("Token läuft ab am: {ExpiryDate}", expiryDate);
            }

            // 1. Benutzer mit Cookie-Authentication anmelden
            logger.LogInformation("Melde Benutzer mit Cookie-Authentication an");

            await SignInUserAsync(userIdentifier, username ?? "unknown", email ?? "unknown@example.com", accessToken,
                refreshToken);

            // 2. Setze reguläre Auth-Cookies für Abwärtskompatibilität
            logger.LogInformation("Setze reguläre Auth-Cookies für Abwärtskompatibilität");
            SetAuthCookies(accessToken, refreshToken, userIdentifier, companyId, expiryDate);

            // 3. Versuche, sichere Verbindungen herzustellen
            try {
                logger.LogInformation("Stelle sichere Verbindungen her");
                await EstablishSecureConnections(userIdentifier, companyId, accessToken, refreshToken);
                logger.LogInformation("Sichere Verbindungen erfolgreich hergestellt");
            }
            catch (Exception connEx) {
                logger.LogWarning(connEx, "Fehler beim Herstellen sicherer Verbindungen: {ErrorMessage}",
                    connEx.Message);
                // Nicht-kritischer Fehler, Weiterleitung trotzdem fortsetzen
            }

            // 4. Bereite Weiterleitungs-URL vor
            var frontendBaseUrl = configuration["Frontend:BaseUrl"] ?? "https://localhost:3000";
            logger.LogDebug("Frontend-Basis-URL aus Konfiguration: '{FrontendBaseUrl}'", frontendBaseUrl);

            // Ersetze Platzhalter in redirectPath durch tatsächliche Werte
            if (redirectPath.Contains("{companyId}")) {
                var originalPath = redirectPath;
                redirectPath = redirectPath.Replace("{companyId}", Uri.EscapeDataString(companyId));

                logger.LogInformation("CompanyId in Weiterleitungspfad ersetzt: {OriginalPath} -> {NewPath}",
                    originalPath, redirectPath);
            }
            else if (!redirectPath.Contains("/dashboard/")) {
                // Wenn Pfad kein Dashboard mit Company enthält, füge es hinzu
                var originalPath = redirectPath;
                redirectPath = $"/dashboard/{Uri.EscapeDataString(companyId)}";

                logger.LogInformation(
                    "Weiterleitung geändert, um Company-Dashboard einzuschließen: {OriginalPath} -> {NewPath}",
                    originalPath, redirectPath);
            }

            // 5. Absolute Weiterleitungs-URL erstellen
            var redirectUrl = BuildRedirectUrl(frontendBaseUrl, redirectPath);

            logger.LogInformation("Leite zum Frontend weiter: {RedirectUrl}", redirectUrl);
            return Redirect(redirectUrl);
        }
        catch (Exception ex) {
            logger.LogError(ex, "Fehler bei der Verarbeitung erfolgreicher Authentifizierung: {ErrorMessage}",
                ex.Message);

            return HandleAuthenticationFailure(new TokenExchangeResult {
                IsSuccessful = false,
                ErrorType = "ProcessingError",
                ErrorDescription = "Fehler bei der Verarbeitung der Authentifizierung: " + ex.Message
            });
        }
    }

    /// <summary>
    /// Builds the redirect URL, handling different URL formats
    /// </summary>
    private string BuildRedirectUrl(string frontendBaseUrl, string redirectPath) {
        // Log incoming parameters
        logger.LogDebug("Building redirect URL with base: {BaseUrl}, path: {Path}",
            frontendBaseUrl, redirectPath);

        // Handle absolute URLs
        if (redirectPath.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) {
            // Force HTTPS
            var secureUrl = string.Concat("https://", redirectPath.AsSpan(7));
            logger.LogInformation("Converting HTTP URL to HTTPS: {Url}", secureUrl);
            return secureUrl;
        }

        if (redirectPath.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) {
            logger.LogInformation("Using absolute HTTPS URL as-is: {Url}", redirectPath);
            return redirectPath;
        }

        // Normalize and combine base URL with path
        frontendBaseUrl = frontendBaseUrl.TrimEnd('/');
        redirectPath = redirectPath.TrimStart('/');

        // Special handling for dashboard with companyId placeholder
        if (redirectPath.Contains("{companyId}")) {
            // We don't have company ID here, so we'll keep the placeholder
            // The frontend will need to handle this replacement
            logger.LogInformation("URL contains companyId placeholder: {Path}", redirectPath);
        }

        var finalUrl = $"{frontendBaseUrl}/{redirectPath}";
        logger.LogInformation("Final redirect URL: {Url}", finalUrl);
        return finalUrl;
    }

    /// <summary>
    /// Authentifiziert den Benutzer mit Cookie-Authentication
    /// </summary>
    /// <param name="userId">Benutzer-ID (sub) aus dem JWT-Token</param>
    /// <param name="username">Benutzername aus dem JWT-Token</param>
    /// <param name="email">E-Mail-Adresse aus dem JWT-Token</param>
    /// <param name="accessToken">Access Token für API-Zugriff</param>
    /// <param name="refreshToken">Refresh Token für Token-Erneuerung</param>
    /// <returns>Task für asynchrone Ausführung</returns>
    private async Task SignInUserAsync(string userId, string username, string email, string accessToken,
        string refreshToken) {
        try {
            logger.LogInformation("Erstelle Claims für Benutzer {UserId}", userId);

            // Erstelle Claims für den Benutzer
            var claims = new List<Claim> {
                new(ClaimTypes.NameIdentifier, userId),
                new(ClaimTypes.Name, username),
                new(ClaimTypes.Email, email),
                new("access_token", accessToken),
                new("refresh_token", refreshToken)
            };

            // Extrahiere Rollen und Gruppen aus dem Token
            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtHandler.ReadJwtToken(accessToken);

            // Extrahiere Rollen aus dem Token
            var roles = ExtractRolesFromToken(jwtToken);
            logger.LogInformation("Gefundene Rollen: {Roles}", string.Join(", ", roles));

            claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

            // Extrahiere Gruppen aus dem Token
            var groups = jwtToken.Claims
                .Where(c => c.Type == "groups")
                .Select(c => c.Value)
                .ToList();

            logger.LogInformation("Gefundene Gruppen: {Groups}", string.Join(", ", groups));

            claims.AddRange(groups.Select(group => new Claim("groups", group)));

            // Erstelle Identity und Principal
            var identity = new ClaimsIdentity(claims, "Cookies");
            var principal = new ClaimsPrincipal(identity);

            // Setze Authentication-Properties
            var authProperties = new AuthenticationProperties {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(8), // An Token-Ablauf anpassen
                AllowRefresh = true
            };

            // Benutzer anmelden
            logger.LogInformation("Melde Benutzer {Username} mit Cookie-Authentication an", username);
            await HttpContext.SignInAsync("Cookies", principal, authProperties);

            logger.LogInformation("Benutzer {Username} erfolgreich mit Cookie-Authentication angemeldet", username);
        }
        catch (Exception ex) {
            logger.LogError(ex, "Fehler beim Anmelden des Benutzers {UserId} mit Cookie-Authentication", userId);
            throw;
        }
    }

    /// <summary>
    /// Extracts roles from JWT token with focus on User Realm Roles
    /// </summary>
    private List<string> ExtractRolesFromToken(JwtSecurityToken jwtToken) {
        var roles = new List<string>();

        try {
            // Search for realm roles
            var realmRolesClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "realm_access")
                                  ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "realm_roles");

            if (realmRolesClaim != null && !string.IsNullOrEmpty(realmRolesClaim.Value)) {
                try {
                    var realmAccess = JsonSerializer.Deserialize<JsonElement>(realmRolesClaim.Value);

                    if (realmAccess.TryGetProperty("roles", out var rolesElement)) {
                        roles.AddRange(rolesElement.EnumerateArray()
                            .Select(role => role.GetString())
                            .Where(roleValue => !string.IsNullOrEmpty(roleValue))!);
                    }
                }
                catch (Exception ex) {
                    logger.LogWarning(ex, "Error deserializing realm_access roles");
                }
            }

            // Alternative: Search for all role-related claims
            var allRolesClaims = jwtToken.Claims.Where(c => c.Type.Contains("role") || c.Type.Contains("Role"));

            foreach (var roleClaim in allRolesClaims) {
                try {
                    // Try to handle both JSON array and single string values
                    if (roleClaim.Value.StartsWith("[") || roleClaim.Value.StartsWith("{")) {
                        var roleJson = JsonSerializer.Deserialize<JsonElement>(roleClaim.Value);

                        if (roleJson.ValueKind == JsonValueKind.Array) {
                            roles.AddRange(roleJson.EnumerateArray()
                                .Select(role => role.GetString())
                                .Where(roleValue => !string.IsNullOrEmpty(roleValue))!);
                        }
                    }
                    else {
                        // Single string value
                        roles.Add(roleClaim.Value);
                    }
                }
                catch {
                    // Fallback to simple string
                    roles.Add(roleClaim.Value);
                }
            }

            // Remove duplicates and empty entries
            roles = roles.Where(r => !string.IsNullOrEmpty(r)).Distinct().ToList();
            logger.LogInformation("Extracted final roles: {Roles}", string.Join(", ", roles));

            return roles;
        }
        catch (Exception ex) {
            logger.LogWarning(ex, "Error extracting roles from token");
            return [];
        }
    }

    /// <summary>
    /// Sets authentication cookies for GraphQL requests with enhanced frontend access
    /// </summary>
    private void SetAuthCookies(
        string accessToken,
        string refreshToken,
        string userId,
        string companyId,
        DateTimeOffset expiryDate) {
        // 1. Access Token Cookie (HTTPOnly for security)
        Response.Cookies.Append("auth_token", accessToken, new CookieOptions {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = expiryDate,
            Path = "/"
        });

        // 2. Zusätzliches Frontend-Token (non-httpOnly für GraphQL im Frontend)
        Response.Cookies.Append("frontend_token", accessToken, new CookieOptions {
            HttpOnly = false, // Zugänglich für Frontend-JavaScript
            Secure = true, // Nur HTTPS
            SameSite = SameSiteMode.None,
            Expires = expiryDate,
            Path = "/"
        });

        // 3. Refresh Token (mehr geschützt)
        Response.Cookies.Append("refresh_token", refreshToken, new CookieOptions {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = expiryDate.AddDays(30), // Längere Gültigkeit für Refresh-Token
            Path = "/"
        });

        // 4. User ID (für Frontend zugänglich)
        Response.Cookies.Append("user_id", userId, new CookieOptions {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = expiryDate,
            Path = "/"
        });

        // 5. Company ID (für Frontend zugänglich)
        Response.Cookies.Append("company_id", companyId, new CookieOptions {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = expiryDate,
            Path = "/"
        });

        // 6. Auth status cookie (für Frontend zugänglich)
        Response.Cookies.Append("auth_status", "authenticated", new CookieOptions {
            HttpOnly = false,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = expiryDate,
            Path = "/"
        });

        logger.LogInformation(
            "Auth cookies set for User {UserId}, Company {CompanyId}, valid until {ExpiryDate}",
            userId, companyId, expiryDate
        );
    }

    /// <summary>
    /// Establishes secure WebSocket and GraphQL connections
    /// </summary>
    private async Task EstablishSecureConnections(
        string userIdentifier,
        string companyId,
        string accessToken,
        string refreshToken) {
        try {
            logger.LogInformation(
                "Establishing secure connections for User {UserId} and Company {CompanyId}",
                userIdentifier, companyId
            );

            // 1. Establish WebSocket connection
            logger.LogInformation("Establishing WebSocket connection...");
            var webSocketConnection = await webSocketManager.CreateConnectionAsync(accessToken);

            logger.LogInformation(
                "WebSocket connection established with ID: {ConnectionId}",
                webSocketConnection.ConnectionId
            );

            // Add additional metadata to WebSocket connection
            webSocketConnection.Metadata["initializationTime"] = DateTime.UtcNow;
            webSocketConnection.Metadata["authMethod"] = "keycloak-oauth";

            // 2. Establish GraphQL HTTP and WebSocket connections
            logger.LogInformation("Establishing GraphQL connections...");

            var graphQlConnection = await graphQlManager.CreateAuthenticatedConnectionAsync(
                new ome.API.GraphQL.Interfaces.GraphQlConnectionParams {
                    UserId = userIdentifier,
                    CompanyId = companyId,
                    AccessToken = accessToken,
                    RefreshToken = refreshToken
                }
            );

            logger.LogInformation(
                "GraphQL connection established with ID: {ConnectionId}",
                graphQlConnection.ConnectionId
            );

            // 3. Initialize tenant context (if needed)
            try {
                await tenantService.InitializeTenantContextAsync(companyId);
                logger.LogInformation("Tenant context initialized for Company {CompanyId}", companyId);
            }
            catch (Exception tenantEx) {
                // Non-critical error - log and continue
                logger.LogWarning(
                    tenantEx,
                    "Could not initialize tenant context, continuing: {ErrorMessage}",
                    tenantEx.Message
                );
            }

            logger.LogInformation(
                "All secure connections successfully established for User {UserId}",
                userIdentifier
            );
        }
        catch (Exception ex) {
            logger.LogError(
                ex,
                "Error establishing secure connections: {ErrorMessage}",
                ex.Message
            );
            throw; // Rethrow to allow caller to handle
        }
    }

    // Response and Parameter Classes

    /// <summary>
    /// Represents the result of a token exchange attempt
    /// </summary>
    public class TokenExchangeResult {
        /// <summary>
        /// Indicates whether the token exchange was successful
        /// </summary>
        public bool IsSuccessful { get; init; }

        /// <summary>
        /// The access token (if successful)
        /// </summary>
        public string? AccessToken { get; init; }

        /// <summary>
        /// The refresh token (if successful)
        /// </summary>
        public string? RefreshToken { get; init; }

        /// <summary>
        /// Error type for failed exchanges
        /// </summary>
        public string? ErrorType { get; init; }

        /// <summary>
        /// Detailed error description
        /// </summary>
        public string? ErrorDescription { get; set; }
    }

    /// <summary>
    /// Represents parameters for creating an authenticated GraphQL connection
    /// </summary>
    public class GraphQlConnectionParams {
        /// <summary>
        /// User identifier
        /// </summary>
        public string UserId { get; set; } = null!;

        /// <summary>
        /// Company/Tenant identifier
        /// </summary>
        public string CompanyId { get; set; } = null!;

        /// <summary>
        /// Access token for authentication
        /// </summary>
        public string AccessToken { get; set; } = null!;

        /// <summary>
        /// Refresh token for maintaining session
        /// </summary>
        public string RefreshToken { get; set; } = null!;
    }

    /// <summary>
    /// Represents a generic error response
    /// </summary>
    public class ErrorResponse {
        /// <summary>
        /// Error message
        /// </summary>
        public string Message { get; set; } = null!;
    }

    /// <summary>
    /// Represents the result of an authentication attempt
    /// </summary>
    public class AuthenticationResult {
        /// <summary>
        /// Indicates whether authentication was successful
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Descriptive message about the authentication result
        /// </summary>
        public string Message { get; set; } = null!;

        /// <summary>
        /// Authenticated user's identifier
        /// </summary>
        public string? UserId { get; set; }

        /// <summary>
        /// Company/Tenant identifier
        /// </summary>
        public string? CompanyId { get; set; }

        /// <summary>
        /// Indicates if secure connections were established
        /// </summary>
        public bool ConnectionsEstablished { get; set; }

        /// <summary>
        /// Redirect URI after authentication
        /// </summary>
        public string RedirectUri { get; set; } = "/";

        /// <summary>
        /// Timestamp of the authentication attempt
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}