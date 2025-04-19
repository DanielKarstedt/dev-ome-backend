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
using Serilog;
using Serilog.Events;
using Serilog.Sinks.SystemConsole.Themes;

namespace ome.API;

public class Program 
{
    // Startup erfolgreiche Phasen tracken
    private static bool _databaseMigrated;
    private static bool _identityConfigured;
    private static bool _middlewareConfigured;
    private static bool _controllersConfigured;
    
    private static void ConfigureLogging(WebApplicationBuilder builder) 
    {
        // Logging-Konfiguration behalten, nur die Ausgabe aufräumen
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

    private static bool _isDatabaseConfigured;
    private static readonly Lock LockObject = new(); // Lock-Object wird als standard object implementiert

    private static void ConfigureDatabaseOptions(IServiceProvider sp, DbContextOptionsBuilder options) 
    {
        lock (LockObject) 
        {
            if (_isDatabaseConfigured) 
            {
                return;
            }
        
            var configuration = sp.GetRequiredService<IConfiguration>();
            var environment = sp.GetRequiredService<IHostEnvironment>();
            var logger = sp.GetRequiredService<ILogger<Program>>();

            try 
            {
                logger.LogInformation("Starte Datenbank-Konfiguration...");
                var connectionString = configuration.GetConnectionString("DefaultConnection");

                connectionString = connectionString?
                    .Replace("${DB_HOST}", Environment.GetEnvironmentVariable("DB_HOST"))
                    .Replace("${DB_PORT}", Environment.GetEnvironmentVariable("DB_PORT"))
                    .Replace("${DB_NAME}", Environment.GetEnvironmentVariable("DB_NAME"))
                    .Replace("${DB_USER}", Environment.GetEnvironmentVariable("DB_USER"))
                    .Replace("${DB_PASSWORD}", Environment.GetEnvironmentVariable("DB_PASSWORD"));

                // CA-Zertifikat prüfen und konfigurieren
                var caPath = Environment.GetEnvironmentVariable("DB_SSL_CA_PATH");
                logger.LogInformation("Prüfe CA-Zertifikat: {CertPath}", caPath);

                if (string.IsNullOrEmpty(caPath))
                {
                    logger.LogCritical("CA-Zertifikatspfad ist nicht gesetzt (DB_SSL_CA_PATH ist leer)");
                    throw new ArgumentNullException("DB_SSL_CA_PATH", "CA-Zertifikatspfad ist nicht konfiguriert");
                }

                if (File.Exists(caPath)) 
                {
                    // Korrekte PostgreSQL-Parameter für SSL mit VerifyFull
                    connectionString += $";SSL Mode=VerifyFull;Root Certificate={caPath}";
                    logger.LogInformation("SSL-Konfiguration mit VerifyFull und Root-CA: {CertPath}", caPath);
                }
                else 
                {
                    logger.LogCritical("CA-Zertifikat nicht gefunden: {CertPath} - Verbindung wird nicht möglich sein",
                        caPath);
                    throw new FileNotFoundException($"Das Root-CA-Zertifikat wurde nicht gefunden: {caPath}", caPath);
                }

                logger.LogInformation("Verbinde zu PostgreSQL mit Sicherheitsstufe VerifyFull");

                options.UseNpgsql(
                    connectionString,
                    npgsqlOptions => 
                    {
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
                if (environment.IsDevelopment()) 
                {
                    options.EnableSensitiveDataLogging();
                    options.EnableDetailedErrors();
                    logger.LogInformation("Entwicklungs-Datenbankoptionen aktiviert");
                }
                else 
                {
                    // Produktions-Logging-Optimierungen
                    options.EnableDetailedErrors(false);
                }

                logger.LogInformation("Datenbankverbindung erfolgreich konfiguriert");
                _isDatabaseConfigured = true;
            }
            catch (Exception ex) 
            {
                logger.LogCritical(ex, "Kritischer Fehler bei Datenbankverbindungskonfiguration");
                throw;
            }
        }
    }

    public static async Task Main(string[] args) 
    {
        // Haupt-Logger für Console-Ausgaben vor der Konfiguration
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .CreateBootstrapLogger();
            
        Log.Information("Starte MultiTenant Backend");
        
        try 
        {
            var builder = WebApplication.CreateBuilder(args);
            
            // 1. Logging konfigurieren
            Log.Information("Konfiguriere Logging...");
            ConfigureLogging(builder);
            
            // 2. Keycloak konfigurieren
            Log.Information("Konfiguriere Keycloak...");
            var keycloakConfig = new Dictionary<string, string?> 
            {
                ["Keycloak:BaseUrl"] = Environment.GetEnvironmentVariable("KEYCLOAK_BASE_URL")
                                       ?? builder.Configuration["Keycloak:BaseUrl"],
                ["Keycloak:Realm"] = Environment.GetEnvironmentVariable("KEYCLOAK_REALM")
                                     ?? builder.Configuration["Keycloak:Realm"],
                ["Keycloak:ClientId"] = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_ID")
                                        ?? builder.Configuration["Keycloak:ClientId"],
                ["Keycloak:ClientSecret"] = Environment.GetEnvironmentVariable("KEYCLOAK_CLIENT_SECRET")
                                            ?? builder.Configuration["Keycloak:ClientSecret"]
            };

            foreach (var config in keycloakConfig.Where(config => !string.IsNullOrEmpty(config.Value))) 
            {
                builder.Configuration[config.Key] = config.Value;
                Log.Information("Keycloak-Konfiguration: {Key}={Value}", config.Key, config.Value);
            }

            // 3. Module laden
            Log.Information("Lade Modul-Einstellungen...");
            var moduleSettings = builder.Configuration.GetSection("Modules").Get<Dictionary<string, bool>>()
                                 ?? new Dictionary<string, bool>();
            Log.Information("Starte MultiTenant Backend mit {ModuleCount} Modulen", moduleSettings.Count);

            // 4. Core Services registrieren
            Log.Information("Registriere Core-Services...");
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddControllers();
            builder.Services.AddHttpContextAccessor();
            builder.Services.AddMemoryCache();

            // 5. Health Checks konfigurieren
            Log.Information("Konfiguriere Health Checks...");
            builder.Services.AddComprehensiveHealthChecks(builder.Configuration);

            // 6. Session-Konfiguration
            Log.Information("Konfiguriere Session...");
            builder.Services.AddSession(options => 
            {
                options.IdleTimeout = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SameSite = SameSiteMode.Lax;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            });
            
            // 7. Logging-Services
            Log.Information("Konfiguriere Logging-Services...");
            builder.Services.AddLoggingServices(builder.Configuration);

            // 8. Scoped Services
            Log.Information("Registriere Tenant- und Identity-Services...");
            builder.Services.AddScoped<ITenantService, TenantService>();
            builder.Services.AddSingleton<TenantHttpRequestInterceptor>();
            builder.Services.AddScoped<ICurrentUserService, CurrentUserService>();
            builder.Services.AddScoped<IKeycloakService, KeycloakService>();

            // 9. Interceptors - REMOVED

            // 10. DbContext konfigurieren
            Log.Information("Konfiguriere Datenbankkontext...");
            builder.Services.AddDbContextFactory<ApplicationDbContext>(ConfigureDatabaseOptions);
            
            // 11. Identity-Services
            Log.Information("Konfiguriere Identity-Services...");
            builder.Services.AddIdentityServices(builder.Configuration);
            _identityConfigured = true;

            // 12. GraphQL
            Log.Information("Konfiguriere GraphQL-Services...");
            builder.Services.AddGraphQlServices(builder.Configuration);

            // 13. Swagger
            Log.Information("Konfiguriere Swagger...");
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerWithAuth(builder.Configuration);

            // 14. Messaging und Events
            Log.Information("Konfiguriere Event-Bus...");
            builder.Services.AddSingleton<IEventBus, InMemoryEventBus>();

            // 15. Module registrieren
            Log.Information("Registriere und konfiguriere Module...");
            var moduleManager = new ModuleManager();
            
            Log.Information("Registriere Auth-Modul...");
            moduleManager.RegisterModule(new AuthModule(), moduleSettings.GetValueOrDefault("Auth", true));
            
            Log.Information("Registriere Users-Modul...");
            moduleManager.RegisterModule(new UsersModule(), moduleSettings.GetValueOrDefault("Users", true));
            
            Log.Information("Registriere Notifications-Modul...");
            moduleManager.RegisterModule(new NotificationsModule(), moduleSettings.GetValueOrDefault("Notifications", true));
            
            Log.Information("Konfiguriere Module-Services...");
            moduleManager.ConfigureServices(builder.Services, builder.Configuration);

            // 16. CORS
            Log.Information("Konfiguriere CORS...");
            builder.Services.AddCors(options => 
            {
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

            // 17. Application bauen
            Log.Information("Baue Anwendung...");
            var app = builder.Build();
            Log.Information("Anwendung erfolgreich gebaut");

            // 18. Datenbank migrieren
            Log.Information("Initialisiere Datenbank...");
            using (var scope = app.Services.CreateScope()) 
            {
                var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

                try 
                {
                    logger.LogInformation("Migriere Datenbank...");
                    await dbContext.Database.MigrateAsync();
                    logger.LogInformation("Datenbank erfolgreich migriert");
                    _databaseMigrated = true;
                }
                catch (Exception ex) 
                {
                    logger.LogError(ex, "Ein Fehler ist bei der Datenbankinitialisierung aufgetreten");
                    throw;
                }
            }

            // 19. Middleware konfigurieren
            Log.Information("Konfiguriere Middleware-Pipeline...");
            
            // CORS-Middleware VOR allen anderen Middleware-Komponenten aktivieren
            Log.Information("Aktiviere CORS...");
            app.UseCors("AllowSpecificOrigins");

            // Umgebungsspezifische Middleware
            Log.Information("Konfiguriere Umgebungsspezifische Middleware...");
            if (app.Environment.IsDevelopment()) 
            {
                app.UseDeveloperExceptionPage();
                Log.Information("Developer Exception Page aktiviert (Entwicklungsumgebung)");
            }
            else if (app.Environment.IsProduction()) 
            {
                app.UseExceptionHandler("/Error");
                app.UseHsts();
                Log.Information("HSTS und Exception Handler aktiviert (Produktionsumgebung)");

                // HTTPS-Weiterleitung für Produktion
                Log.Information("Aktiviere HTTPS-Weiterleitung...");
                app.UseHttpsRedirection();

                // Forwarded Headers für Reverse-Proxy
                Log.Information("Konfiguriere Header-Weiterleitung für Reverse-Proxy...");
                app.UseForwardedHeaders(new ForwardedHeadersOptions 
                {
                    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
                });
            }

            // 20. Swagger
            Log.Information("Aktiviere Swagger...");
            app.UseSwagger();
            app.UseSwaggerUI(c => 
            {
                c.SwaggerEndpoint("/swagger/v1/swagger.json", "MultiTenant API v1");
                c.RoutePrefix = "swagger";
            });

            // 21. Serilog Request Logging
            Log.Information("Konfiguriere Request-Logging...");
            app.UseSerilogRequestLogging(options => 
            {
                options.MessageTemplate = "HTTP {RequestMethod} {RequestPath} responded {StatusCode} in {Elapsed:0.0000} ms";
                options.EnrichDiagnosticContext = (diagnosticContext, httpContext) => 
                {
                    if (httpContext.Request.Host.Value != null) 
                    {
                        diagnosticContext.Set("Host", httpContext.Request.Host.Value);
                    }
                    diagnosticContext.Set("UserAgent", httpContext.Request.Headers["User-Agent"].FirstOrDefault() ?? string.Empty);
                };
            });

            // 22. Standard Middleware
            Log.Information("Konfiguriere Standard-Middleware...");
            app.UseStaticFiles();
            app.UseSession();
            app.UseAuthentication();
            app.UseAuthorization();
            
            // 23. Routing & Controllers
            Log.Information("Konfiguriere Endpunkte...");
            app.MapControllers();
            app.MapGraphQL().RequireCors("AllowSpecificOrigins");
            app.MapDetailedHealthChecks();
            _controllersConfigured = true;

            // 24. WebSockets
            Log.Information("Konfiguriere WebSockets...");
            app.UseWebSockets(new WebSocketOptions 
            {
                KeepAliveInterval = TimeSpan.FromMinutes(2)
            });
            _middlewareConfigured = true;

            // 25. Kestrel-Konfiguration überprüfen
            Log.Information("Überprüfe Server-Konfiguration...");
            var urls = app.Urls.ToList();
            if (urls.Count == 0)
            {
                Log.Warning("WARNUNG: Keine URL für Kestrel konfiguriert. Die Anwendung wird möglicherweise nicht auf externe Anfragen hören.");
                Log.Information("Setze Standard-URL für Kestrel auf http://0.0.0.0:8080");
                app.Urls.Add("http://0.0.0.0:8080");
            }
            Log.Information("Server wird auf folgenden URLs lauschen: {Urls}", string.Join(", ", app.Urls));

            // 26. Server starten
            Log.Information("Starte Webserver...");
            try
            {
                // RunAsync() durch Run() ersetzen für blockierenden Aufruf
                await app.RunAsync();
                // Diese Zeile wird nur erreicht, wenn der Server beendet wurde
                Log.Information("Webserver ordnungsgemäß beendet");
            }
            catch (Exception ex)
            {
                Log.Fatal(ex, "Webserver unerwartet gestoppt");
                throw;
            }
        }
        catch (Exception ex) 
        {
            // Status-Tracking für Fehlerbehebung
            Log.Fatal("Status-Tracking: DatabaseMigrated={0}, IdentityConfigured={1}, MiddlewareConfigured={2}, ControllersConfigured={3}", 
                _databaseMigrated, _identityConfigured, _middlewareConfigured, _controllersConfigured);
                
            Log.Fatal(ex, "Host wurde unerwartet beendet");
            throw;
        }
        finally 
        {
            Log.Information("Anwendung wird beendet...");
            await Log.CloseAndFlushAsync();
        }
    }
}