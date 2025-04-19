using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Reflection;
using Microsoft.AspNetCore.Authorization;
using Path = System.IO.Path;

namespace ome.API.Extensions;

/// <summary>
/// Erweiterungen für die Swagger-Konfiguration
/// </summary>
public static class SwaggerExtensions {
    /// <summary>
    /// Fügt Swagger mit Authentifizierungsunterstützung hinzu
    /// </summary>
    public static IServiceCollection AddSwaggerWithAuth(this IServiceCollection services,
        IConfiguration configuration) {
        var keycloakSettings = configuration.GetSection("Keycloak");

        var authUrl =
            $"{keycloakSettings["BaseUrl"]}/auth/realms/{keycloakSettings["Realm"]}/protocol/openid-connect/auth";

        var tokenUrl =
            $"{keycloakSettings["BaseUrl"]}/auth/realms/{keycloakSettings["Realm"]}/protocol/openid-connect/token";

        services.AddSwaggerGen(c =>
        {
            c.SwaggerDoc("v1", new OpenApiInfo
            {
                Title = "MultiTenant API",
                Version = "v1",
                Description = "API für das MultiTenant-Backend mit GraphQL und REST-Endpunkten",
                Contact = new OpenApiContact
                {
                    Name = "Support",
                    Email = "support@example.com"
                }
            });

            // 1. OAuth2-Authentifizierung (für Keycloak)
            c.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.OAuth2,
                Flows = new OpenApiOAuthFlows
                {
                    Implicit = new OpenApiOAuthFlow
                    {
                        AuthorizationUrl = new Uri(authUrl),
                        TokenUrl = new Uri(tokenUrl),
                        Scopes = new Dictionary<string, string>
                        {
                            { "openid", "OpenID" },
                            { "profile", "Profilinformationen" },
                            { "email", "E-Mail-Adresse" }
                        }
                    }
                },
                Description = "OAuth2-Authentifizierung über Keycloak"
            });

            // 2. Neue Cookie-Authentifizierung für Swagger
            c.AddSecurityDefinition("CookieAuth", new OpenApiSecurityScheme
            {
                Description = "Cookie-basierte Authentifizierung. Zuerst bei /api/Auth/login anmelden.",
                Name = "OfficeMadeEasyAuth",
                In = ParameterLocation.Cookie,
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Cookie"
            });

            // 3. Auch Bearer-Token-Authentifizierung unterstützen
            c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
            {
                Description = "JWT Authorization header using the Bearer scheme. Beispiel: \"Authorization: Bearer {token}\"",
                Name = "Authorization",
                In = ParameterLocation.Header,
                Type = SecuritySchemeType.ApiKey,
                Scheme = "Bearer"
            });

            // Sicherheitsanforderungen für Swagger
            c.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
                // OAuth2
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "oauth2"
                        }
                    },
                    ["openid", "profile", "email"]
                },
                // Cookie Auth
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "CookieAuth"
                        }
                    },
                    []
                },
                // Bearer Auth
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    []
                }
            });

            // Füge XML-Kommentare hinzu
            // Dadurch werden die XML-Dokumentationskommentare in Swagger angezeigt
            try 
            {
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                if (File.Exists(xmlPath))
                {
                    c.IncludeXmlComments(xmlPath);
                }
            }
            catch (Exception ex)
            {
                // Fehler beim Laden der XML-Datei sollten nicht zum Absturz führen
                Console.WriteLine($"Warnung: XML-Kommentare konnten nicht geladen werden: {ex.Message}");
            }

            // Aktiviere Swagger-Erweiterungen hier
            c.EnableAnnotations();

            // Filter für Authentifizierungs-Attribute
            c.OperationFilter<AuthenticationOperationFilter>();

            // Benutzerdefinierten Filter für Controller-Dokumentation hinzufügen
            c.DocumentFilter<SwaggerRoleBasedFilter>();
        });

        return services;
    }
}

/// <summary>
/// Filter, dere bestimmte Controller und Aktionen basierend auf Rollen anzigt
/// </summary>
public class SwaggerRoleBasedFilter: IDocumentFilter {
    public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context) {
        // Filtere API-Endpunkte basierend auf Rollen
        // Hier könnten wir beispielsweise bestimmte Endpunkte für bestimmte Rollen ausblenden

        // Da wir in diesem Fall hauptsächlich GraphQL verwenden, ist dieser Filter eher für zukünftige REST-Endpunkte relevant
    }
}

/// <summary>
/// Fügt Authentifizierungsanforderungen zu Swagger-Operationen hinzu, die [Authorize]-Attribute verwenden
/// </summary>
public class AuthenticationOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        // Prüfe, ob Controller oder Methode das [Authorize]-Attribut hat
        var authAttributes = context.MethodInfo.DeclaringType?.GetCustomAttributes(true)
            .Union(context.MethodInfo.GetCustomAttributes(true))
            .OfType<AuthorizeAttribute>();

        if (!authAttributes!.Any()) return;
        // Füge mögliche Antwortcodes hinzu
        operation.Responses.TryAdd("401", new OpenApiResponse { Description = "Nicht authentifiziert" });
        operation.Responses.TryAdd("403", new OpenApiResponse { Description = "Zugriff verweigert" });
            
        var securityRequirements = new List<OpenApiSecurityRequirement>
        {
            // OAuth2-Anforderung
            new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "oauth2"
                        }
                    },
                    ["openid", "profile", "email"]
                }
            },
            // Cookie-Auth-Anforderung
            new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "CookieAuth"
                        }
                    },
                    []
                }
            },
            // Bearer-Auth-Anforderung
            new OpenApiSecurityRequirement
            {
                {
                    new OpenApiSecurityScheme
                    {
                        Reference = new OpenApiReference
                        {
                            Type = ReferenceType.SecurityScheme,
                            Id = "Bearer"
                        }
                    },
                    []
                }
            }
        };
            
        operation.Security = securityRequirements;
    }
}