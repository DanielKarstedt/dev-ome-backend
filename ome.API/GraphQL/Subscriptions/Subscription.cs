using HotChocolate.Execution;
using HotChocolate.Subscriptions;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Logging;


namespace ome.API.GraphQL.Subscriptions;

/// <summary>
/// GraphQL-Subscriptions für Echtzeit-Updates
/// </summary>
[GraphQLDescription("Subscriptions für Echtzeit-Updates")]
public class Subscription(ILogger<Subscription> logger) {

    // BENUTZER-SUBSCRIPTIONS

    [GraphQLDescription("Wird aufgerufen, wenn ein neuer Benutzer erstellt wird")]
    [Subscribe(MessageType = typeof(UserCreatedNotification))]
    public async ValueTask<ISourceStream<UserCreatedNotification>> OnUserCreated(
        [Service] ITopicEventReceiver eventReceiver,
        [Service] ICurrentUserService currentUserService,
        [Service] ITenantService tenantService,
        CancellationToken cancellationToken) {
        logger.LogDebug("Subscription: OnUserCreated registriert");

        // Prüfe, ob der aktuelle Benutzer berechtigt ist, diese Subscription zu nutzen
        if (currentUserService.IsInRole("OmeAdmin") || currentUserService.IsInRole("OmeSuperUser"))
        {
            return await eventReceiver.SubscribeAsync<UserCreatedNotification>(
                nameof(OnUserCreated),
                cancellationToken);
        }

        logger.LogWarning("Unbefugter Zugriff auf OnUserCreated-Subscription durch Benutzer {UserId}",
            currentUserService.UserId);

        throw new UnauthorizedAccessException(
            "Sie haben keine Berechtigung, Benutzer-Erstellung-Benachrichtigungen zu abonnieren.");
    }

    [GraphQLDescription("Wird aufgerufen, wenn ein Benutzer aktualisiert wird")]
    [Subscribe(MessageType = typeof(UserUpdatedNotification))]
    public async ValueTask<ISourceStream<UserUpdatedNotification>> OnUserUpdated(
        [Service] ITopicEventReceiver eventReceiver,
        [Service] ICurrentUserService currentUserService,
        [Service] ITenantService tenantService,
        CancellationToken cancellationToken) {
        logger.LogDebug("Subscription: OnUserUpdated registriert");

        // Prüfe, ob der aktuelle Benutzer berechtigt ist, diese Subscription zu nutzen
        if (currentUserService.IsInRole("OmeAdmin") || currentUserService.IsInRole("OmeSuperUser"))
        {
            return await eventReceiver.SubscribeAsync<UserUpdatedNotification>(
                nameof(OnUserUpdated),
                cancellationToken);
        }

        logger.LogWarning("Unbefugter Zugriff auf OnUserUpdated-Subscription durch Benutzer {UserId}",
            currentUserService.UserId);

        throw new UnauthorizedAccessException(
            "Sie haben keine Berechtigung, Benutzer-Aktualisierung-Benachrichtigungen zu abonnieren.");
    }

    [GraphQLDescription("Wird aufgerufen, wenn ein Benutzer gelöscht wird")]
    [Subscribe(MessageType = typeof(UserDeletedNotification))]
    public async ValueTask<ISourceStream<UserDeletedNotification>> OnUserDeleted(
        [Service] ITopicEventReceiver eventReceiver,
        [Service] ICurrentUserService currentUserService,
        [Service] ITenantService tenantService,
        CancellationToken cancellationToken) {
        logger.LogDebug("Subscription: OnUserDeleted registriert");

        // Tenant-Berechtigungsprüfung für Subscriptions
        var tenantId = tenantService.GetCurrentTenantId();

        // Prüfe, ob der aktuelle Benutzer berechtigt ist, diese Subscription zu nutzen
        if (currentUserService.IsInRole("OmeAdmin") || currentUserService.IsInRole("OmeSuperUser"))
        {
            return await eventReceiver.SubscribeAsync<UserDeletedNotification>(
                nameof(OnUserDeleted),
                cancellationToken);
        }

        logger.LogWarning("Unbefugter Zugriff auf OnUserDeleted-Subscription durch Benutzer {UserId}",
            currentUserService.UserId);

        throw new UnauthorizedAccessException(
            "Sie haben keine Berechtigung, Benutzer-Löschung-Benachrichtigungen zu abonnieren.");
    }

// LOGGING-SUBSCRIPTIONS

    [GraphQLDescription("Abonniert Logs für den aktuellen Tenant (nur für Administratoren und Tech-User)")]
    [Subscribe(MessageType = typeof(LogEntryDto))]
    public async ValueTask<ISourceStream<LogEntryDto>> OnLogCreated(
        [Service] ITopicEventReceiver eventReceiver,
        [Service] ICurrentUserService currentUserService,
        [Service] ITenantService tenantService,
        [Service] GraphQlLogProvider logProvider,
        CancellationToken cancellationToken) {
        logger.LogDebug("Subscription: OnLogCreated registriert");

        // Tenant-Berechtigungsprüfung für Subscriptions
        var tenantId = tenantService.GetCurrentTenantId();

        // Prüfe, ob der aktuelle Benutzer berechtigt ist, diese Subscription zu nutzen
        if (currentUserService.IsInRole("OmeAdmin") || currentUserService.IsInRole("OmeTechUser") ||
            currentUserService.IsInRole("OmeSuperUser"))
        {
            return await eventReceiver.SubscribeAsync<LogEntryDto>(
                nameof(OnLogCreated),
                cancellationToken);
        }

        logger.LogWarning("Unbefugter Zugriff auf OnLogCreated-Subscription durch Benutzer {UserId}",
            currentUserService.UserId);

        throw new UnauthorizedAccessException(
            "Sie haben keine Berechtigung, Log-Benachrichtigungen zu abonnieren.");
    }
}
// Benachrichtigungsobjekte für Subscriptions

/// <summary>
/// Benachrichtigung über die Erstellung eines Benutzers
/// </summary>
public class UserCreatedNotification {
    [GraphQLDescription("Die ID des erstellten Benutzers")]
    public Guid UserId { get; set; }

    [GraphQLDescription("Der Benutzername des erstellten Benutzers")]
    public string Username { get; set; } = null!;

    [GraphQLDescription("Der Benutzer, der den Benutzer erstellt hat")]
    public string CreatedBy { get; set; } = null!;

    [GraphQLDescription("Die ID des Tenants")]
    public Guid TenantId { get; set; }

    [GraphQLDescription("Der Zeitpunkt der Erstellung")]
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Benachrichtigung über die Aktualisierung eines Benutzers
/// </summary>
public class UserUpdatedNotification {
    [GraphQLDescription("Die ID des aktualisierten Benutzers")]
    public Guid UserId { get; set; }

    [GraphQLDescription("Der Benutzername des aktualisierten Benutzers")]
    public string Username { get; set; } = null!;

    [GraphQLDescription("Der Benutzer, der den Benutzer aktualisiert hat")]
    public string UpdatedBy { get; set; } = null!;

    [GraphQLDescription("Die ID des Tenants")]
    public Guid TenantId { get; set; }

    [GraphQLDescription("Der Zeitpunkt der Aktualisierung")]
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>
/// Benachrichtigung über die Löschung eines Benutzers
/// </summary>
public class UserDeletedNotification {
    [GraphQLDescription("Die ID des gelöschten Benutzers")]
    public Guid UserId { get; set; }

    [GraphQLDescription("Der Benutzername des gelöschten Benutzers")]
    public string Username { get; set; } = null!;

    [GraphQLDescription("Der Benutzer, der den Benutzer gelöscht hat")]
    public string DeletedBy { get; set; } = null!;

    [GraphQLDescription("Die ID des Tenants")]
    public Guid TenantId { get; set; }

    [GraphQLDescription("Der Zeitpunkt der Löschung")]
    public DateTime DeletedAt { get; set; } = DateTime.UtcNow;
}