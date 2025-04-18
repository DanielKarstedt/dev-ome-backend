using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Identity.Keycloak;

public class KeycloakService: IKeycloakService {
    private readonly HttpClient _httpClient;
    private readonly KeycloakSettings _settings;
    private readonly ILogger<KeycloakService> _logger;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly bool _isDevelopment;

    public KeycloakService(
        HttpClient httpClient,
        IConfiguration configuration,
        IHostEnvironment environment,
        ILogger<KeycloakService> logger) {
        _httpClient = httpClient;
        _logger = logger;
        _tokenHandler = new JwtSecurityTokenHandler();
        _isDevelopment = environment.IsDevelopment();

        // Dynamische Konfigurationsauflösung
        _settings = ResolveCoolifyConfiguration(configuration);

        // Konfiguriere den HTTP-Client
        _httpClient.BaseAddress = new Uri(_settings.BaseUrl);
        _httpClient.DefaultRequestHeaders.Accept.Clear();
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        // Nur in Entwicklungsumgebung loggen
        if (_isDevelopment) {
            LogKeycloakConfiguration();
        }
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
        // Sicheres Logging ohne sensible Daten - nur in Entwicklungsumgebung
        _logger.LogInformation(
            "Keycloak-Konfiguration: " +
            "BaseUrl={BaseUrl}, " +
            "Realm={Realm}, " +
            "ClientId={ClientId}",
            _settings.BaseUrl,
            _settings.Realm,
            _settings.ClientId
        );
    }

    /// <summary>
    /// Generiert die Autorisierungs-URL für den OAuth-Flow
    /// </summary>
    public string GetAuthorizationUrl(string redirectUri, string state) {
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
            // Grundlegende Eingabevalidierung
            if (string.IsNullOrWhiteSpace(code)) {
                throw new ArgumentException("Autorisierungscode ist ungültig", nameof(code));
            }

            if (string.IsNullOrWhiteSpace(redirectUri)) {
                throw new ArgumentException("Redirect-URI ist erforderlich", nameof(redirectUri));
            }

            var tokenEndpoint = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/token";

            var content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "authorization_code",
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = _settings.ClientSecret,
                ["code"] = code,
                ["redirect_uri"] = redirectUri
            });

            // Retry-Mechanismus mit exponentiellem Backoff
            int maxRetries = 2;

            for (int retry = 0; retry <= maxRetries; retry++) {
                if (retry > 0) {
                    // Exponentieller Backoff
                    int delayMs = (int)Math.Pow(2, retry) * 500;
                    await Task.Delay(delayMs, cancellationToken);
                }

                try {
                    var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

                    if (!response.IsSuccessStatusCode) {
                        var errorContent = await response.Content.ReadAsStringAsync(cancellationToken);
                        
                        // Nur wenn letzter Retry fehlschlägt, loggen und Exception werfen
                        if (retry == maxRetries) {
                            _logger.LogError(
                                "Token-Austausch fehlgeschlagen: StatusCode={StatusCode}",
                                response.StatusCode
                            );
                            throw new InvalidOperationException(
                                $"Token-Austausch nach {maxRetries} Versuchen fehlgeschlagen."
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
                        
                        if (retry == maxRetries) {
                            _logger.LogError("Ungültige Token-Antwort erhalten");
                            throw new InvalidOperationException("Ungültige Token-Antwort");
                        }
                        continue;
                    }

                    return (tokenResponse.AccessToken, tokenResponse.RefreshToken);
                }
                catch (HttpRequestException httpEx) {
                    if (retry == maxRetries) {
                        _logger.LogError(
                            httpEx,
                            "Netzwerkfehler während Token-Austausch"
                        );
                        throw;
                    }
                }
            }

            throw new InvalidOperationException("Token-Austausch nach Retries fehlgeschlagen");
        }
        catch (Exception ex) {
            _logger.LogError(
                ex,
                "Fehler beim Token-Austausch"
            );
            throw;
        }
    }

    private static string ExtractErrorType(string errorContent) {
        try {
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
            var tokenEndpoint = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/token";

            var content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["grant_type"] = "refresh_token",
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = _settings.ClientSecret,
                ["refresh_token"] = refreshToken
            });

            var response = await _httpClient.PostAsync(tokenEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode) {
                _logger.LogError("Token-Aktualisierung fehlgeschlagen: StatusCode={StatusCode}", response.StatusCode);
                throw new InvalidOperationException($"Token-Aktualisierung fehlgeschlagen");
            }

            var responseJson = await response.Content.ReadAsStringAsync(cancellationToken);
            var tokenResponse = JsonSerializer.Deserialize<KeycloakTokenResponse>(responseJson);

            return tokenResponse!.AccessToken;
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Fehler bei Token-Aktualisierung");
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
            var logoutEndpoint = $"{_settings.BaseUrl}/realms/{_settings.Realm}/protocol/openid-connect/logout";

            var content = new FormUrlEncodedContent(new Dictionary<string, string> {
                ["refresh_token"] = refreshToken,
                ["client_id"] = _settings.ClientId,
                ["client_secret"] = _settings.ClientSecret
            });

            var response = await _httpClient.PostAsync(logoutEndpoint, content, cancellationToken);

            if (!response.IsSuccessStatusCode && _isDevelopment) {
                _logger.LogWarning("Logout nicht erfolgreich: {StatusCode}", response.StatusCode);
            }
        }
        catch (Exception ex) {
            // Nur als Warnung loggen, da Logout nicht kritisch ist
            _logger.LogWarning(ex, "Fehler beim Logout");
        }
    }

    /// <summary>
    /// Validiert ein Token
    /// </summary>
    public async Task<bool> ValidateTokenAsync(
        string token,
        CancellationToken cancellationToken = default) {
        try {
            var baseUrl = _settings.BaseUrl;
            var realm = _settings.Realm;
            var clientId = _settings.ClientId;
            var validateIssuer = _settings.ValidateIssuer;
            var validateAudience = _settings.ValidateAudience;

            // Hole die JWKS-URL
            var jwksEndpoint = $"{baseUrl}/realms/{realm}/protocol/openid-connect/certs";

            var jwksResponse = await _httpClient.GetAsync(jwksEndpoint, cancellationToken);

            if (!jwksResponse.IsSuccessStatusCode) {
                _logger.LogError("JWKS-Abruf fehlgeschlagen: {StatusCode}", jwksResponse.StatusCode);
                return false;
            }

            var jwksJson = await jwksResponse.Content.ReadAsStringAsync(cancellationToken);
            var jwks = JsonSerializer.Deserialize<JsonWebKeySet>(jwksJson);

            if (jwks?.Keys == null || !jwks.Keys.Any()) {
                _logger.LogError("Keine gültigen Schlüssel in JWKS gefunden");
                return false;
            }

            // Konvertiere JWKS-Schlüssel zu Microsoft.IdentityModel.Tokens.SecurityKey
            var securityKeys = jwks.Keys.Select(key => {
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
                catch {
                    return null;
                }
            }).Where(k => k != null).ToList();

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
                    return false;
                }

                // Prüfe Ablaufzeit mit zusätzlicher Sicherheitsmarge
                var utcNow = DateTime.UtcNow;

                return validatedToken.ValidFrom <= utcNow &&
                       validatedToken.ValidTo > utcNow.AddMinutes(-1);
            }
            catch (Exception ex) {
                if (_isDevelopment) {
                    _logger.LogWarning(ex, "Token-Validierung fehlgeschlagen");
                }
                return false;
            }
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Unerwarteter Fehler bei Token-Validierung");
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
            var jwtToken = _tokenHandler.ReadJwtToken(token);

            // Suche nach dem Tenant-Claim
            var tenantClaim = jwtToken.Claims.FirstOrDefault(c => c.Type == "tenant_id" || c.Type == "tenantId");

            if (tenantClaim == null) {
                return Task.FromResult(Guid.Empty);
            }

            if (Guid.TryParse(tenantClaim.Value, out var tenantId)) {
                return Task.FromResult(tenantId);
            }

            return Task.FromResult(Guid.Empty);
        }
        catch (Exception ex) {
            _logger.LogError(ex, "Fehler beim Extrahieren der Tenant-ID aus Token");
            return Task.FromResult(Guid.Empty);
        }
    }

    /// <summary>
    /// Extrahiert die Informationen aus einem Token
    /// </summary>
    public Task<TokenInfo> GetTokenInfoAsync(string token, CancellationToken cancellationToken = default) {
        try {
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
            _logger.LogError(ex, "Fehler beim Extrahieren von Token-Informationen");
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