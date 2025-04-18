using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Identity.Keycloak;

public class KeycloakService: IKeycloakService {
    private readonly HttpClient _httpClient;
    private readonly KeycloakSettings _settings;
    private readonly ILogger<KeycloakService> _logger;
    private readonly JwtSecurityTokenHandler _tokenHandler;

    public KeycloakService(
        HttpClient httpClient,
        IConfiguration configuration,
        ILogger<KeycloakService> logger) {
        _httpClient = httpClient;
        _logger = logger;
        _tokenHandler = new JwtSecurityTokenHandler();

        // Dynamische Konfigurationsauflösung
        _settings = ResolveCoolifyConfiguration(configuration);

        // Konfiguriere den HTTP-Client
        _httpClient.BaseAddress = new Uri(_settings.BaseUrl);
        _httpClient.DefaultRequestHeaders.Accept.Clear();
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // Umfangreiches Logging der Konfiguration
        LogKeycloakConfiguration();
    }

    private KeycloakSettings ResolveCoolifyConfiguration(IConfiguration configuration) {
        var settings = new KeycloakSettings {
            BaseUrl = ResolveSetting("Keycloak:BaseUrl", "KEYCLOAK_BASE_URL", "https://auth.officemadeeasy.eu"),
            Realm = ResolveSetting("Keycloak:Realm", "KEYCLOAK_REALM", "officemadeeasy"),
            ClientId = ResolveSetting("Keycloak:ClientId", "KEYCLOAK_CLIENT_ID", "c#-backend-client"),
            ClientSecret = ResolveSetting("Keycloak:ClientSecret", "KEYCLOAK_CLIENT_SECRET"),
            ValidateIssuer = configuration.GetValue("Keycloak:ValidateIssuer", true),
            ValidateAudience = configuration.GetValue("Keycloak:ValidateAudience", true),
            RequireHttpsMetadata = configuration.GetValue("Keycloak:RequireHttpsMetadata", true)
        };

        // Validiere Konfiguration
        ValidateKeycloakSettings(settings);

        return settings;

        // Methode zur Auflösung von Konfigurationen aus verschiedenen Quellen
        string ResolveSetting(string configKey, string environmentVariableName, string defaultValue = null!) {
            // Priorität: 1. Konfiguration, 2. Umgebungsvariable, 3. Standardwert
            return configuration[configKey]
                   ?? Environment.GetEnvironmentVariable(environmentVariableName)
                   ?? defaultValue
                   ?? throw new InvalidOperationException($"Konfiguration für {configKey} nicht gefunden");
        }
    }

    private void ValidateKeycloakSettings(KeycloakSettings settings) {
        var validationErrors = new List<string>();

        if (string.IsNullOrWhiteSpace(settings.BaseUrl))
            validationErrors.Add("Keycloak-Basis-URL fehlt");

        if (string.IsNullOrWhiteSpace(settings.Realm))
            validationErrors.Add("Realm nicht konfiguriert");

        if (string.IsNullOrWhiteSpace(settings.ClientId))
            validationErrors.Add("Client-ID fehlt");

        if (string.IsNullOrWhiteSpace(settings.ClientSecret))
            validationErrors.Add("Client-Geheimnis fehlt");

        if (validationErrors.Count == 0) {
            return;
        }

        var errorMessage = string.Join(", ", validationErrors);

        _logger.LogCritical(
            "Keycloak-Konfigurationsfehler: {ErrorMessage}",
            errorMessage
        );

        throw new InvalidOperationException(
            $"Keycloak-Konfiguration ungültig: {errorMessage}"
        );
    }

    private void LogKeycloakConfiguration() {
        // Sicheres Logging ohne sensible Daten
        _logger.LogInformation(
            "Keycloak-Konfiguration: " +
            "BaseUrl={BaseUrl}, " +
            "Realm={Realm}, " +
            "ClientId={ClientId}, " +
            "ValidateIssuer={ValidateIssuer}, " +
            "ValidateAudience={ValidateAudience}",
            _settings.BaseUrl,
            _settings.Realm,
            _settings.ClientId,
            _settings.ValidateIssuer,
            _settings.ValidateAudience
        );
    }

// Restliche Klassen (KeycloakSettings, KeycloakTokenResponse, etc.) bleiben unverändert
    /// <summary>
    /// Generiert die Autorisierungs-URL für den OAuth-Flow
    /// </summary>
    public string GetAuthorizationUrl(string redirectUri, string state) {
        // Korrigierter Pfad ohne "/auth"
        var authUrl = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/auth";

        var queryParams = new Dictionary<string, string> {
            ["response_type"] = "code",
            ["client_id"] = _settings.ClientId,
            ["redirect_uri"] = redirectUri,
            ["state"] = state,
            ["scope"] = "openid profile email"
        };

        var queryString = string.Join("&", queryParams.Select(kv => $"{kv.Key}={Uri.EscapeDataString(kv.Value)}"));
        return $"{authUrl}?{queryString}";
    }

    /// <summary>
    /// Tauscht den Autorisierungscode gegen Tokens aus
    /// </summary>
    public async Task<(string AccessToken, string RefreshToken)> ExchangeCodeForTokenAsync(
        string code,
        string redirectUri,
        CancellationToken cancellationToken = default) {
        try {
            // Grundlegende Eingabevalidierung mit Sicherheits-Logging
            if (string.IsNullOrWhiteSpace(code)) {
                _logger.LogWarning("Ungültiger Autorisierungscode: Leer oder Whitespace");
                throw new ArgumentException("Autorisierungscode ist ungültig", nameof(code));
            }

            if (string.IsNullOrWhiteSpace(redirectUri)) {
                _logger.LogWarning("Ungültige Redirect-URI");
                throw new ArgumentException("Redirect-URI ist erforderlich", nameof(redirectUri));
            }

            // Log partial code for debugging (only first few chars)
            string codePrefix = code.Length > 4 ? code.Substring(0, 4) + "..." : "...";
            _logger.LogInformation("Starte Token-Austausch mit Code-Prefix: {CodePrefix}", codePrefix);

            var tokenEndpoint = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/token";

            // Sicheres Logging ohne sensible Daten
            _logger.LogDebug(
                "Token-Austausch-Konfiguration: Endpoint={TokenEndpoint}, ClientId={ClientId}, RedirectUri={RedirectUri}",
                tokenEndpoint,
                _settings.ClientId,
                redirectUri
            );

            // Create the form with ACTUAL values (not masked ones)
            var content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = _settings.ClientSecret, // Real secret, not masked
                ["code"] = code, // Real code, not masked
                ["redirect_uri"] = redirectUri
            });

            // Create sanitized version for logging (if needed)
            var sanitizedValues = new Dictionary<string, string> {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = "********",
                ["code"] = "********",
                ["redirect_uri"] = redirectUri
            };

            _logger.LogDebug("Sending token request with parameters: {Params}",
                string.Join(", ", sanitizedValues.Select(kv => $"{kv.Key}={kv.Value}")));

            // Retry-Mechanismus mit exponentiellem Backoff
            int maxRetries = 2;

            for (int retry = 0; retry <= maxRetries; retry++) {
                if (retry > 0) {
                    // Exponentieller Backoff
                    int delayMs = (int)Math.Pow(2, retry) * 500;

                    _logger.LogInformation(
                        "Token-Austausch-Retry {RetryCount}/{MaxRetries}, Verzögerung {DelayMs}ms",
                        retry, maxRetries, delayMs
                    );
                    await Task.Delay(delayMs, cancellationToken);
                }

                try {
                    var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

                    // Strukturiertes Logging für Antwort-Status
                    _logger.LogInformation(
                        "Token-Austausch-Antwort: StatusCode={StatusCode}",
                        response.StatusCode
                    );

                    if (!response.IsSuccessStatusCode) {
                        var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);

                        // Log error content for debugging (be careful with sensitive data)
                        string safeErrorContent = errorContent;

                        // If error is too large, truncate it
                        if (safeErrorContent.Length > 500) {
                            safeErrorContent = safeErrorContent.Substring(0, 500) + "...";
                        }

                        _logger.LogWarning(
                            "Token-Austausch fehlgeschlagen: StatusCode={StatusCode}, Error={Error}",
                            response.StatusCode,
                            safeErrorContent
                        );

                        // Nur letzter Retry wirft Exception
                        if (retry == maxRetries) {
                            throw new InvalidOperationException(
                                $"Token-Austausch nach {maxRetries} Versuchen fehlgeschlagen. Error: {ExtractErrorType(errorContent)}"
                            );
                        }

                        continue; // Nächster Retry
                    }

                    var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
                    var tokenResponse = JsonSerializer.Deserialize<KeycloakTokenResponse>(responseJson);

                    // Validierung der Token-Antwort
                    if (tokenResponse == null ||
                        string.IsNullOrEmpty(tokenResponse.AccessToken) ||
                        string.IsNullOrEmpty(tokenResponse.RefreshToken)) {
                        _logger.LogWarning(
                            "Ungültige Token-Antwort: AccessToken={AccessTokenStatus}, RefreshToken={RefreshTokenStatus}",
                            tokenResponse?.AccessToken != null,
                            tokenResponse?.RefreshToken != null
                        );

                        if (retry == maxRetries) {
                            throw new InvalidOperationException("Ungültige Token-Antwort");
                        }

                        continue;
                    }

                    // Erfolgs-Logging mit minimalen Informationen
                    _logger.LogInformation(
                        "Token-Austausch erfolgreich: TokenType={TokenType}, Gültig für {ExpiresIn}s",
                        tokenResponse.TokenType,
                        tokenResponse.ExpiresIn
                    );

                    return (tokenResponse.AccessToken, tokenResponse.RefreshToken);
                }
                catch (HttpRequestException httpEx) {
                    // Netzwerkfehler-Logging
                    _logger.LogWarning(
                        httpEx,
                        "Netzwerkfehler während Token-Austausch: Retry {Retry}/{MaxRetries}",
                        retry,
                        maxRetries
                    );

                    if (retry == maxRetries) {
                        throw;
                    }
                }
            }

            throw new InvalidOperationException("Token-Austausch nach Retries fehlgeschlagen");
        }
        catch (Exception ex) {
            // Generische Fehler-Logging-Strategie
            _logger.LogError(
                ex,
                "Unerwarteter Fehler beim Token-Austausch: Typ={ExceptionType}",
                ex.GetType().Name
            );
            throw;
        }
    }

// Hilfsmethode zur Extraktion des Fehlertyps
    private static string ExtractErrorType(string errorContent) {
        try {
            // Versuche, den Fehlertyp zu extrahieren, ohne sensible Daten zu loggen
            var errorDict = JsonSerializer.Deserialize<Dictionary<string, string>>(errorContent);
            return errorDict?.GetValueOrDefault("error", "UnbekannterFehler") ?? "UnbekannterFehler";
        }
        catch {
            return "ParsingFehler";
        }
    }

    /// <summary>
    /// Erneuert ein Token mithilfe eines Refresh-Tokens
    /// </summary>
    public async Task<string> RefreshTokenAsync(
        string refreshToken,
        CancellationToken cancellationToken = default) {
        try {
            _logger.LogDebug("Refreshing token");

            // Korrigierter Pfad ohne "/auth"
            var tokenEndpoint = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/token";

            var content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = _settings.ClientSecret,
                ["refresh_token"] = refreshToken
            });

            var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode) {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);

                _logger.LogWarning("Token refresh failed. Status code: {StatusCode}, Error: {Error}",
                    response.StatusCode, errorContent);
                throw new InvalidOperationException($"Token refresh failed: {response.StatusCode}");
            }

            var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
            var tokenResponse = JsonSerializer.Deserialize<KeycloakTokenResponse>(responseJson);

            _logger.LogInformation("Token refresh successful");

            return tokenResponse!.AccessToken;
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Error during token refresh");
            throw;
        }
    }

    /// <summary>
    /// Führt den Logout-Vorgang durch
    /// </summary>
    public async Task LogoutAsync(
        string refreshToken,
        CancellationToken cancellationToken = default) {
        try {
            _logger.LogDebug("Logging out user");

            // Korrigierter Pfad ohne "/auth"
            var logoutEndpoint = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/logout";

            var content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["refresh_token"] = refreshToken,
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = _settings.ClientSecret
            });

            var response = await _httpClient.PostAsync(logoutEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode) {
                var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);

                _logger.LogWarning("Logout failed. Status code: {StatusCode}, Error: {Error}",
                    response.StatusCode, errorContent);
                // Wir werfen hier keine Exception, da der Logout-Vorgang nicht kritisch ist
            }

            _logger.LogInformation("Logout successful");
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Error during logout");
            // Wir werfen hier keine Exception, da der Logout-Vorgang nicht kritisch ist
        }
    }

    /// <summary>
    /// Validiert ein Token
    /// </summary>
    /// <summary>
    /// Validiert ein Token
    /// </summary>
    public async Task<bool> ValidateTokenAsync(
        string token,
        CancellationToken cancellationToken = default) {
        try {
            _logger.LogDebug("Validating token");

            var baseUrl = _settings.BaseUrl;
            var realm = _settings.Realm;
            var clientId = _settings.ClientId;
            var validateIssuer = _settings.ValidateIssuer;
            var validateAudience = _settings.ValidateAudience;

            // Hole die JWKS-URL
            var jwksEndpoint = $"{baseUrl}/realms/{realm}/protocol/openid-connect/certs";

            _logger.LogInformation("JWKS Endpoint: {Endpoint}", jwksEndpoint);

            var jwksResponse = await _httpClient.GetAsync(jwksEndpoint, cancellationToken);

            if (!jwksResponse.IsSuccessStatusCode) {
                var responseBody = await jwksResponse.Content.ReadAsStringAsync(cancellationToken);

                _logger.LogWarning(
                    "Failed to retrieve JWKS. Status code: {StatusCode}, Response: {ResponseBody}",
                    jwksResponse.StatusCode,
                    responseBody
                );
                return false;
            }

            var jwksJson = await jwksResponse.Content.ReadAsStringAsync(cancellationToken);
            var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(jwksJson);

            if (jwks?.Keys == null || !jwks.Keys.Any()) {
                _logger.LogWarning("No valid keys found in JWKS");
                return false;
            }

            // Konvertiere JWKS-Schlüssel zu Microsoft.IdentityModel.Tokens.SecurityKey
            var securityKeys = jwks.Keys.Select(key => {
                _logger.LogInformation($"Processing Key: KID={key.KeyId}, Alg={key.Algorithm}");

                try {
                    // Konvertiere Base64-kodierte Modulus und Exponent
                    var modulusBytes = Base64UrlEncoder.DecodeBytes(key.Modulus);
                    var exponentBytes = Base64UrlEncoder.DecodeBytes(key.Exponent);

                    var rsa = new System.Security.Cryptography.RSACryptoServiceProvider();

                    rsa.ImportParameters(new System.Security.Cryptography.RSAParameters {
                        Modulus = modulusBytes,
                        Exponent = exponentBytes
                    });

                    return new RsaSecurityKey(rsa) {
                        KeyId = key.KeyId
                    };
                }
                catch (Exception ex) {
                    _logger.LogError(ex, $"Fehler bei Schlüssel-Konvertierung für Key ID {key.KeyId}");
                    return null;
                }
            }).Where(k => k != null).ToList();

            _logger.LogInformation($"Konvertierte Schlüssel: {securityKeys.Count}");

            // Token für Debugging extrahieren
            var jwtToken = _tokenHandler.ReadJwtToken(token);
            var tokenKeyId = jwtToken.Header.Kid;
            _logger.LogInformation($"Token Key ID: {tokenKeyId}");

            var validationParameters = new TokenValidationParameters {
                ValidateIssuer = validateIssuer,
                ValidIssuer = $"{baseUrl}/realms/{realm}",
                ValidateAudience = validateAudience,
                ValidAudience = clientId,
                ValidAudiences = [clientId, "account"],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1),
                RequireExpirationTime = true,
                RequireSignedTokens = true,
                IssuerSigningKeys = securityKeys
            };

            try {
                // Validiere das Token
                _tokenHandler.ValidateToken(token, validationParameters, out var validatedToken);

                // Zusätzliche Prüfungen
                if (validatedToken == null) {
                    _logger.LogWarning("Token validation resulted in null validated token");
                    return false;
                }

                // Prüfe Ablaufzeit mit zusätzlicher Sicherheitsmarge
                var utcNow = DateTime.UtcNow;

                var isValid = validatedToken.ValidFrom <= utcNow &&
                              validatedToken.ValidTo > utcNow.AddMinutes(-1);

                if (!isValid) {
                    _logger.LogWarning("Token is expired or not yet valid");
                    return false;
                }

                return true;
            }
            catch (Exception ex) {
                _logger.LogWarning(ex, "Token validation failed");
                _logger.LogWarning($"Exception Details: {ex.Message}");
                return false;
            }
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Unexpected error during token validation");
            return false;
        }
    }

    /// <summary>
    /// Extrahiert die TenantId aus einem Token
    /// </summary>
    public Task<Guid> GetTenantIdFromTokenAsync(
        string token,
        CancellationToken cancellationToken = default) {
        try {
            _logger.LogDebug("Extracting tenant ID from token");

            var jwtToken = _tokenHandler.ReadJwtToken(token);

            // Suche nach dem Tenant-Claim
            var tenantClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "tenant_id" || c.Type == "tenantId");

            if (tenantClaim == null) {
                _logger.LogWarning("No tenant ID claim found in token");
                return Task.FromResult(Guid.Empty);
            }

            if (Guid.TryParse(tenantClaim.Value, out var tenantId)) {
                _logger.LogInformation("Extracted tenant ID {TenantId} from token", tenantId);
                return Task.FromResult(tenantId);
            }

            _logger.LogWarning("Invalid tenant ID format in token: {TenantId}", tenantClaim.Value);
            return Task.FromResult(Guid.Empty);
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Error extracting tenant ID from token");
            return Task.FromResult(Guid.Empty);
        }
    }

    /// <summary>
    /// Extrahiert die Informationen aus einem Token
    /// </summary>
    public Task<TokenInfo> GetTokenInfoAsync(string token, CancellationToken cancellationToken = default) {
        try {
            _logger.LogDebug("Extracting token information");

            var jwtToken = _tokenHandler.ReadJwtToken(token);

            var tokenInfo = new TokenInfo {
                UserId = jwtToken.Claims.FirstOrDefault(c => c.Type == "sub")?.Value,
                Username = jwtToken.Claims.FirstOrDefault(c => c.Type == "preferred_username")?.Value,
                Email = jwtToken.Claims.FirstOrDefault(c => c.Type == "email")?.Value,
                TenantId = jwtToken.Claims.FirstOrDefault(c => c.Type is "tenant_id" or "tenantId")?.Value,
                ExpiresAt = jwtToken.ValidTo,
                Roles = jwtToken.Claims.Where(c => c.Type == "roles").Select(c => c.Value).ToList()
            };

            return Task.FromResult(tokenInfo);
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Error extracting token information");
            throw;
        }
    }
}

/// <summary>
/// Konfigurationseinstellungen für Keycloak
/// </summary>
public class KeycloakSettings {
    public string BaseUrl { get; init; } = null!;
    public string Realm { get; init; } = null!;
    public string ClientId { get; init; } = null!;
    public string ClientSecret { get; init; } = null!;
    public bool ValidateIssuer { get; init; } = true;
    public bool ValidateAudience { get; init; } = true;
    public bool RequireHttpsMetadata { get; init; } = true;
}

/// <summary>
/// Antwortmodell für Token-Antworten von Keycloak
/// </summary>
public class KeycloakTokenResponse {
    [JsonPropertyName("access_token")] public string AccessToken { get; init; } = null!;

    [JsonPropertyName("expires_in")] public int ExpiresIn { get; init; }

    [JsonPropertyName("refresh_token")] public string RefreshToken { get; init; } = null!;

    [JsonPropertyName("refresh_expires_in")]
    public int RefreshExpiresIn { get; init; }

    [JsonPropertyName("token_type")] public string TokenType { get; init; } = null!;

    [JsonPropertyName("scope")] public string Scope { get; init; } = null!;
}

/// <summary>
/// Modell für JSON Web Key Set
/// </summary>
public class JsonWebKeySet {
    [JsonPropertyName("keys")] public List<JsonWebKey> Keys { get; init; } = null!;
}

/// <summary>
/// Modell für JSON Web Key
/// </summary>
public class JsonWebKey: SecurityKey {
    [JsonPropertyName("kty")] public string KeyType { get; set; } = null!;

    [JsonPropertyName("kid")] public new string KeyId { get; set; } = null!;

    [JsonPropertyName("use")] public string Use { get; set; } = null!;

    [JsonPropertyName("n")] public string Modulus { get; set; } = null!;

    [JsonPropertyName("e")] public string Exponent { get; set; } = null!;

    [JsonPropertyName("alg")] public string Algorithm { get; set; } = null!;

    [JsonPropertyName("x5c")] public string[] X509Certificates { get; set; } = null!;

    public override int KeySize => 2048; // Default für RSA
}