using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Identity.Keycloak;
using ome.Infrastructure.Identity.Services;

namespace ome.Infrastructure.Identity.Extensions;

/// <summary>
/// Erweiterungen für die Registrierung von Identity-Diensten
/// </summary>
public static class IdentityServiceExtensions {
    /// <summary>
    /// Fügt die Identity-Dienste dem Dependency Injection Container hinzu
    /// </summary>
    public static IServiceCollection
        AddIdentityServices(this IServiceCollection services, IConfiguration configuration) {
        // Konfiguriere Keycloak-Authentifizierung
        var keycloakSettings = configuration.GetSection("Keycloak").Get<KeycloakSettings>();

        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(options =>
            {
                options.Authority = $"{keycloakSettings!.BaseUrl}/auth/realms/{keycloakSettings.Realm}";
                options.Audience = keycloakSettings.ClientId;
                options.RequireHttpsMetadata = keycloakSettings.RequireHttpsMetadata;

                // Token-Validierungsparameter
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = keycloakSettings.ValidateIssuer,
                    ValidateAudience = keycloakSettings.ValidateAudience,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ClockSkew = TimeSpan.Zero
                };

                // Unterstützung für WebSockets
                options.Events = new JwtBearerEvents
                {
                    OnMessageReceived = context =>
                    {
                        // Ermöglicht die Verwendung des Tokens in WebSocket-Verbindungen
                        var accessToken = context.Request.Query["access_token"];
                        var path = context.HttpContext.Request.Path;

                        if (!string.IsNullOrEmpty(accessToken) && path.StartsWithSegments("/graphql"))
                        {
                            context.Token = accessToken;
                        }

                        return Task.CompletedTask;
                    }
                };
            });

        // Füge Autorisierungs-Policies hinzu
        services.AddAuthorization(options =>
        {
            // Beispiel-Policies für die verschiedenen Rollen
            options.AddPolicy("RequireAdminRole", policy =>
                policy.RequireRole("OmeAdmin"));

            options.AddPolicy("RequireDeputyAdminRole", policy =>
                policy.RequireRole("OmeAdmin", "OmeDeputyAdmin"));

            options.AddPolicy("RequireOfficeWorkerRole", policy =>
                policy.RequireRole("OmeAdmin", "OmeDeputyAdmin", "OmeOfficeWorker"));

            options.AddPolicy("RequireSuperUserRole", policy =>
                policy.RequireRole("OmeAdmin", "OmeDeputyAdmin", "OmeSuperUser"));

            options.AddPolicy("RequireTechUserRole", policy =>
                policy.RequireRole("OmeAdmin", "OmeDeputyAdmin", "OmeSuperUser", "OmeTechUser"));

            options.AddPolicy("RequireTechnicianRole", policy =>
                policy.RequireRole("OmeAdmin", "OmeDeputyAdmin", "OmeSuperUser", "OmeTechnician"));

            options.AddPolicy("RequireTechnicianManagerRole", policy =>
                policy.RequireRole("OmeAdmin", "OmeDeputyAdmin", "OmeSuperUser", "OmeTechnicianManager"));
        });

        // Registriere Http-Dienste
        services.AddHttpContextAccessor();
        services.AddHttpClient<IKeycloakService, KeycloakService>();

        // Registriere Identity-Dienste
        services.AddScoped<ICurrentUserService, CurrentUserService>();
        services.AddScoped<ITenantService, TenantService>();
        services.AddScoped<IKeycloakService, KeycloakService>();

        return services;
    }
}