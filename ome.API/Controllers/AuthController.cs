using System.IdentityModel.Tokens.Jwt;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using System.Web;
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
    /// Generates a login URL for Keycloak authentication
    /// </summary>
    /// <param name="redirectUri">Optional redirect URI after successful login</param>
    /// <returns>Login URL details</returns>
    [HttpGet("login")]
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
            const string callbackUrl = "https://dev.api.officemadeeasy.eu/api/Auth/callback";
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
    /// Handles OAuth callback from Keycloak
    /// </summary>
    /// <param name="code">Authorization code from Keycloak</param>
    /// <param name="state">State parameter for CSRF protection</param>
    /// <returns>Authentication result</returns>
    [HttpGet("callback")]
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
            const string callbackUrl = "https://dev.api.officemadeeasy.eu/api/Auth/callback";
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
    /// Handles authentication failure with appropriate logging and redirection
    /// </summary>
    private IActionResult HandleAuthenticationFailure(TokenExchangeResult result) {
        var frontendBaseUrl = configuration["Frontend:BaseUrl"] ?? "https://localhost:3000";
        var errorMessage = result.ErrorType ?? "auth_failed";

        logger.LogWarning("Authentication failed. Redirecting to error page. Error: {ErrorMessage}", errorMessage);

        return Redirect($"{frontendBaseUrl.TrimEnd('/')}/error?message={errorMessage}");
    }

    /// <summary>
    /// Processes successful authentication after token exchange
    /// </summary>
    private async Task<IActionResult> ProcessSuccessfulAuthentication(
        string accessToken,
        string refreshToken,
        string redirectPath) {
        try {
            // JWT Token decoding and claims extraction
            var jwtHandler = new JwtSecurityTokenHandler();
            var jwtToken = jwtHandler.ReadJwtToken(accessToken);

            // Extract user identifier
            var userIdentifier = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value;

            if (string.IsNullOrEmpty(userIdentifier)) {
                logger.LogWarning("No user ID (sub) found in token");

                return HandleAuthenticationFailure(new TokenExchangeResult {
                    IsSuccessful = false,
                    ErrorType = "NoUserId",
                    ErrorDescription = "User identifier not found in token"
                });
            }

            // Extract company ID - supports multiple claim types
            var companyId = jwtToken.Claims.FirstOrDefault(c => c.Type == "company")?.Value
                            ?? jwtToken.Claims.FirstOrDefault(c => c.Type == "groups")?.Value;

            if (string.IsNullOrEmpty(companyId)) {
                logger.LogWarning("No company ID found for user");

                return HandleAuthenticationFailure(new TokenExchangeResult {
                    IsSuccessful = false,
                    ErrorType = "NoCompanyId",
                    ErrorDescription = "Company identifier not found in token"
                });
            }

            // Handle company ID in path format
            if (companyId.Contains('/')) {
                var originalCompanyId = companyId;
                companyId = companyId.Split("/").LastOrDefault() ?? companyId;

                logger.LogInformation("Extracted company ID from path: {OriginalId} -> {ExtractedId}",
                    originalCompanyId, companyId);
            }

            // Extract roles
            var roles = ExtractRolesFromToken(jwtToken);
            logger.LogInformation("Extracted roles: {Roles}", string.Join(", ", roles));

            // Extract token expiry time
            var expiryTimestamp = jwtToken.Claims.FirstOrDefault(c => c.Type == "exp")?.Value;
            var expiryDate = DateTimeOffset.UtcNow.AddHours(1); // Default: 1 hour

            if (!string.IsNullOrEmpty(expiryTimestamp) && long.TryParse(expiryTimestamp, out var unixTime)) {
                expiryDate = DateTimeOffset.FromUnixTimeSeconds(unixTime);
                logger.LogInformation("Token expires at: {ExpiryDate}", expiryDate);
            }

            // Set authentication cookies
            SetAuthCookies(accessToken, refreshToken, userIdentifier, companyId, expiryDate);

            // Attempt to establish secure connections
            try {
                await EstablishSecureConnections(userIdentifier, companyId, accessToken, refreshToken);
                logger.LogInformation("Secure connections successfully established");
            }
            catch (Exception connEx) {
                logger.LogWarning(connEx, "Error establishing secure connections: {ErrorMessage}", connEx.Message);
                // Non-critical error, continue with redirect
            }

            // Prepare redirect URL
            var frontendBaseUrl = configuration["Frontend:BaseUrl"] ?? "https://localhost:3000";
            logger.LogDebug("Frontend Base URL from configuration: '{FrontendBaseUrl}'", frontendBaseUrl);

            // Replace placeholders in redirectPath with actual values
            if (redirectPath.Contains("{companyId}")) {
                var originalPath = redirectPath;
                redirectPath = redirectPath.Replace("{companyId}", Uri.EscapeDataString(companyId));

                logger.LogInformation("Replaced companyId in redirect path: {OriginalPath} -> {NewPath}",
                    originalPath, redirectPath);
            }
            else if (!redirectPath.Contains("/dashboard/")) {
                // If path doesn't include dashboard with company, add it
                var originalPath = redirectPath;
                redirectPath = $"/dashboard/{Uri.EscapeDataString(companyId)}";

                logger.LogInformation("Changed redirect to include company dashboard: {OriginalPath} -> {NewPath}",
                    originalPath, redirectPath);
            }

            // Build absolute redirect URL
            var redirectUrl = BuildRedirectUrl(frontendBaseUrl, redirectPath);

            logger.LogInformation("Redirecting to frontend: {RedirectUrl}", redirectUrl);
            return Redirect(redirectUrl);
        }
        catch (Exception ex) {
            logger.LogError(ex, "Error during successful authentication processing: {ErrorMessage}", ex.Message);

            return HandleAuthenticationFailure(new TokenExchangeResult {
                IsSuccessful = false,
                ErrorType = "ProcessingError",
                ErrorDescription = "Failed to process authentication: " + ex.Message
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