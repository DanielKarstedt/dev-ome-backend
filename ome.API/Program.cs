using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.EntityFrameworkCore;
using ome.API.Extensions;
using ome.API.GraphQL.Extensions;
using ome.API.GraphQL.Middlewares;
using ome.Core.Features.Auth;
using ome.Core.Features.Notifications;
using ome.Core.Features.Users;
using ome.Core.Interfaces.Messaging;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.HealthChecks;
using ome.Infrastructure.Identity.Extensions;
using ome.Infrastructure.Identity.Keycloak;
using ome.Infrastructure.Identity.Services;
using ome.Infrastructure.Logging;
using ome.Infrastructure.Modules;
using ome.Infrastructure.Persistence.Context;
using ome.Infrastructure.Persistence.Interceptors;
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

namespace ome.API;

public class Program {
    private static void ConfigureLogging(WebApplicationBuilder builder) {
        Log.Logger = new LoggerConfiguration()
            .MinimumLevel.Information()
            .MinimumLevel.Override("Microsoft", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.Hosting.Lifetime", LogEventLevel.Information)
            .MinimumLevel.Override("System", LogEventLevel.Warning)
            .MinimumLevel.Override("Microsoft.EntityFrameworkCore", LogEventLevel.Warning)
            .WriteTo.Console(
                outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj}{NewLine}{Exception}",
                theme: AnsiConsoleTheme.Code
            )
            .WriteTo.File(
                path: "logs/application-.log",
                rollingInterval: RollingInterval.Day,
                retainedFileCountLimit: 7,
                outputTemplate: "{Timestamp:yyyy-MM-dd HH:mm:ss.fff zzz} [{Level:u3}] {Message:lj}{NewLine}{Exception}"
            )
            .Enrich.FromLogContext()
            .Enrich.WithEnvironmentName()
            .Enrich.WithMachineName()
            .CreateLogger();

        builder.Host.UseSerilog();
    }

    private static void ConfigureDatabaseOptions(IServiceProvider sp, DbContextOptionsBuilder options) {
        var configuration = sp.GetRequiredService<IConfiguration>();
        var environment = sp.GetRequiredService<IHostEnvironment>();
        var logger = sp.GetRequiredService<ILogger<Program>>();

        try {
            var connectionString = configuration.GetConnectionString("DefaultConnection");

            connectionString = connectionString?
                .Replace("${DB_HOST}", Environment.GetEnvironmentVariable("DB_HOST"))
                .Replace("${DB_PORT}", Environment.GetEnvironmentVariable("DB_PORT"))
                .Replace("${DB_NAME}", Environment.GetEnvironmentVariable("DB_NAME"))
                .Replace("${DB_USER}", Environment.GetEnvironmentVariable("DB_USER"))
                .Replace("${DB_PASSWORD}", Environment.GetEnvironmentVariable("DB_PASSWORD"));

            // Pfad zum Coolify CA-Zertifikat aus Umgebungsvariable oder Standardpfad
            var caPath = Environment.GetEnvironmentVariable("DB_SSL_CA_PATH");

            if (File.Exists(caPath)) {
                // Korrekte PostgreSQL-Parameter für SSL mit VerifyFull
                connectionString += $";SSL Mode=VerifyFull;Root Certificate={caPath}";
                logger.LogInformation("SSL-Konfiguration mit VerifyFull und Root-CA: {CertPath}", caPath);
            }
            else {
                logger.LogCritical("CA-Zertifikat nicht gefunden: {CertPath} - Verbindung wird nicht möglich sein",
                    caPath);
                throw new FileNotFoundException($"Das Root-CA-Zertifikat wurde nicht gefunden: {caPath}", caPath);
            }

            logger.LogInformation("Verbinde zu PostgreSQL mit Sicherheitsstufe VerifyFull");

            options.UseNpgsql(
                connectionString,
                npgsqlOptions => {
                    // Migrations-Assembly
                    npgsqlOptions.MigrationsAssembly(typeof(ApplicationDbContext).Assembly.FullName);

                    // Robuster Retry-Mechanismus
                    npgsqlOptions.EnableRetryOnFailure(
                        maxRetryCount: environment.IsDevelopment() ? 3 : 10,
                        maxRetryDelay: TimeSpan.FromSeconds(environment.IsDevelopment() ? 15 : 60),
                        errorCodesToAdd: null
                    );

                    // Performance & Stability Optimierungen
                    npgsqlOptions.UseQuerySplittingBehavior(QuerySplittingBehavior.SplitQuery);
                    npgsqlOptions.CommandTimeout(120); // 2 Minuten Timeout
                }
            );

            // Entwicklungsumgebung spezifische Konfiguration
            if (environment.IsDevelopment()) {
                options.EnableSensitiveDataLogging();
                options.EnableDetailedErrors();
                logger.LogInformation("Entwicklungs-Datenbankoptionen aktiviert");
            }
            else {
                // Produktions-Logging-Optimierungen
                options.EnableDetailedErrors(false);
            }

            logger.LogInformation("Datenbankverbindung erfolgreich konfiguriert");
        }
        catch (Exception ex) {
            logger.LogCritical(ex, "Kritischer Fehler bei Datenbankverbindungskonfiguration");
            throw;
        }
    }


    private static void AddCustomInterceptors(IServiceProvider sp, DbContextOptionsBuilder options) {
        try {
            // Versuche die Services zu bekommen, aber akzeptiere wenn sie null sind
            var auditInterceptor = sp.GetService<AuditSaveChangesInterceptor>();
            var tenantInterceptor = sp.GetService<TenantSaveChangesInterceptor>();

            if (auditInterceptor != null) {
                options.AddInterceptors(auditInterceptor);
            }

            if (tenantInterceptor != null) {
                options.AddInterceptors(tenantInterceptor);
            }

            Log.Information("Interceptors erfolgreich konfiguriert");
        }
        catch (Exception ex) {
            Log.Warning(ex, "Fehler bei der Konfiguration der Interceptors");
            // Hier keine Exception werfen, damit die Migration durchlaufen kann
        }
    }

    public static async Task Main(string[] args) {
        var builder = WebApplication.CreateBuilder(args);
        Log.Information("Starte MultiTenant Backend");

        var keycloakConfig = new Dictionary<string, string?> {
            ["Keycloak:BaseUrl"] = Environment.GetEnvironmentVariable("KEYCLOAK_BASE_URL")
                                   ?? builder.Configuration["Keycloak:BaseUrl"],
            ["Keycloak:Realm"] = Environment.GetEnvironmentVariable("KEYCLOAK_REALM")
                                 ?? builder.Configuration["Keycloak:Realm"],
            ["Keycloak:ClientId"] = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_ID")
                                    ?? builder.Configuration["Keycloak:ClientId"],
            ["Keycloak:ClientSecret"] = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_SECRET")
                                        ?? builder.Configuration["Keycloak:ClientSecret"]
        };

        // Aktualisiere Konfiguration
        foreach (var config in keycloakConfig.Where(config => !string.IsNullOrEmpty(config.Value))) {
            builder.Configuration[config.Key] = config.Value;
        }

        try {
            ConfigureLogging(builder);

            var moduleSettings = builder.Configuration.GetSection("Modules").Get<Dictionary<string, bool>>()
                                 ?? new Dictionary<string, bool>();

            Log.Information("Starte MultiTenant Backend mit {ModuleCount} Modulen", moduleSettings.Count);

            // Services registrieren
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddControllers();
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddMemoryCache();

            // Health Checks hinzufügen
            builder.Services.AddComprehensiveHealthChecks(builder.Configuration);

            builder.Services.AddSession(options => {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });
            builder.Services.AddLoggingServices(builder.Configuration);

            // Scoped Services
            builder.Services.AddScoped<ITenantService, TenantService>();
            builder.Services.AddSingleton<TenantHttpRequestInterceptor>();
            builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();
            builder.Services.AddScoped<IKeycloakService, KeycloakService>();

            // Interceptors als Scoped registrieren
            builder.Services.AddScoped<AuditSaveChangesInterceptor>();
            builder.Services.AddScoped<TenantSaveChangesInterceptor>();

            // DbContext Konfiguration
            builder.Services.AddDbContextFactory<ApplicationDbContext>((sp, options) => {
                ConfigureDatabaseOptions(sp, options);

                try {
                    // Versuchen die Interceptors zu holen, aber ignorieren wenn nicht verfügbar
                    AddCustomInterceptors(sp, options);
                }
                catch (Exception ex) {
                    Log.Warning(ex,
                        "Interceptors konnten nicht geladen werden - wird für Design-Time-Context ignoriert");
                }
            });
            // Identität und Authentifizierung
            builder.Services.AddIdentityServices(builder.Configuration);

            // GraphQL
            builder.Services.AddGraphQlServices(builder.Configuration);

            // Swagger
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerWithAuth(builder.Configuration);

            // Messaging und Events
            builder.Services.AddSingleton<IEventBus, InMemoryEventBus>();

            // Modulregistrierung
            var moduleManager = new ModuleManager();
            moduleManager.RegisterModule(new AuthModule(), moduleSettings.GetValueOrDefault("Auth", true));
            moduleManager.RegisterModule(new UsersModule(), moduleSettings.GetValueOrDefault("Users", true));

            moduleManager.RegisterModule(new NotificationsModule(),
                moduleSettings.GetValueOrDefault("Notifications", true));
            moduleManager.ConfigureServices(builder.Services, builder.Configuration);

            // CORS
            builder.Services.AddCors(options => {
                options.AddPolicy("AllowSpecificOrigins",
                    policy => policy
                        .WithOrigins(
                            "https://localhost:3000",
                            "https://auth.officemadeeasy.eu"
                        )
                        .AllowAnyMethod()
                        .AllowAnyHeader()
                        .WithExposedHeaders("Authorization", "Content-Type")
                        .AllowCredentials());
            });

            var app = builder.Build();
            Log.Information("Anwendung erfolgreich gebaut");

            // Datenbank-Initialisierung
            using (var scope = app.Services.CreateScope()) {
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

                try {
                    logger.LogInformation("Migriere Datenbank...");
                    await dbContext.Database.MigrateAsync();
                    logger.LogInformation("Datenbank erfolgreich migriert");
                }
                catch (Exception ex) {
                    logger.LogError(ex, "Ein Fehler ist bei der Datenbankinitialisierung aufgetreten");
                    throw;
                }
            }

            // CORS-Middleware VOR allen anderen Middleware-Komponenten aktivieren (für alle Umgebungen)
            app.UseCors("AllowSpecificOrigins");

            // HTTP-Pipeline-Konfiguration
            if (app.Environment.IsDevelopment()) {
                app.UseDeveloperExceptionPage();
            }
            else if (app.Environment.IsProduction()) {
                app.UseExceptionHandler("/Error");
                app.UseHsts();

                // HTTPS-Weiterleitung aktivieren
                app.UseHttpsRedirection();


                // Weitergeleitete Header verarbeiten (z.B. hinter einem Reverse Proxy)
                app.UseForwardedHeaders(new ForwardedHeadersOptions {
                    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
                });
            }

            app.UseSwagger();

            app.UseSwaggerUI(c => {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenant API v1");
                c.RoutePrefix = "swagger";
            });

            app.UseSerilogRequestLogging(options => {
                options.MessageTemplate =
                    "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";

                options.EnrichDiagnosticContext = (diagnosticContext, httpContext) => {
                    if (httpContext.Request.Host.Value != null) {
                        diagnosticContext.Set("Host", httpContext.Request.Host.Value);
                    }

                    diagnosticContext.Set("UserAgent",
                        httpContext.Request.Headers["User-Agent"].FirstOrDefault() ?? string.Empty);
                };
            });

            app.UseStaticFiles();
            app.UseSession();
            app.UseAuthentication();
            app.UseAuthorization();
            app.MapControllers();
            app.MapGraphQL().RequireCors("AllowSpecificOrigins");
            app.MapDetailedHealthChecks();

            app.UseWebSockets(new WebSocketOptions {
                KeepAliveInterval = TimeSpan.FromMinutes(2)
            });

            Log.Information("Starte Anwendung...");
            await app.RunAsync();
        }
        catch (Exception ex) {
            Log.Fatal(ex, "Host wurde unerwartet beendet");
            throw;
        }
        finally {
            await Log.CloseAndFlushAsync();
        }
    }
}