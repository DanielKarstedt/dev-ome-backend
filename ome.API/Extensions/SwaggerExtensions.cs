using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;

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

                // Füge OAuth2-Authentifizierung hinzu
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
                    }
                });

                c.AddSecurityRequirement(new OpenApiSecurityRequirement
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
                });

                // Füge XML-Kommentare hinzu
                // Dadurch werden die XML-Dokumentationskommentare in Swagger angezeigt
                // var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                // var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                // c.IncludeXmlComments(xmlPath);

                // Aktiviere Swagger-Erweiterungen hier
                c.EnableAnnotations();

                // Benutzerdefinierten Filter für Controller-Dokumentation hinzufügen
                c.DocumentFilter<SwaggerRoleBasedFilter>();
            });

            return services;
        }
    }

    /// <summary>
    /// Filter, der bestimmte Controller und Aktionen basierend auf Rollen anzeigt
    /// </summary>
    public class SwaggerRoleBasedFilter: IDocumentFilter {
        public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context) {
            // Filtere API-Endpunkte basierend auf Rollen
            // Hier könnten wir beispielsweise bestimmte Endpunkte für bestimmte Rollen ausblenden

            // Da wir in diesem Fall hauptsächlich GraphQL verwenden, ist dieser Filter eher für zukünftige REST-Endpunkte relevant
        }
    }