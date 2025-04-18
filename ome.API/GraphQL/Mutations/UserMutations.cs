using HotChocolate.Subscriptions;
using Microsoft.EntityFrameworkCore;
using ome.API.GraphQL.Subscriptions;
using ome.Core.Domain.Entities.Users;
using ome.Core.Domain.Enums;
using ome.Core.Domain.Events.Users;
using ome.Core.Interfaces.Messaging;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Persistence.Context;

namespace ome.API.GraphQL.Mutations;

[ExtendObjectType("Mutation")]
public class UserMutations(ILogger<UserMutations> logger) {

    [GraphQLDescription("Erstellt einen neuen Benutzer")]
    public async Task<CreateUserPayload> CreateUser(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService,
        [Service] ITopicEventSender eventSender,
        [Service] IEventBus eventBus,
        CreateUserInput input,
        CancellationToken cancellationToken) {
        logger.LogInformation("Mutation: CreateUser mit Benutzername {Username}", input.Username);

        // Berechtigungsprüfung
        if (!currentUserService.IsInRole("OmeAdmin") && !currentUserService.IsInRole("OmeSuperUser"))
        {
            logger.LogWarning("Unbefugter Zugriff auf CreateUser durch Benutzer {UserId}",
                currentUserService.UserId);
            throw new UnauthorizedAccessException("Sie haben keine Berechtigung, Benutzer anzulegen.");
        }

        var tenantId = currentUserService.TenantId;

        // Prüfe, ob Benutzername oder E-Mail bereits existieren
        var existingUser = await dbContext.Users
            .AnyAsync(u => (u.Username == input.Username || u.Email == input.Email) &&
                           u.TenantId == tenantId && !u.IsDeleted,
                cancellationToken);

        if (existingUser)
        {
            logger.LogWarning(
                "Versuch, einen Benutzer mit bereits existierendem Benutzernamen oder E-Mail anzulegen: {Username}, {Email}",
                input.Username, input.Email);

            throw new GraphQLException(
                "Ein Benutzer mit diesem Benutzernamen oder dieser E-Mail existiert bereits.");
        }

        // Erstelle neuen Benutzer
        var user = new User
        {
            Id = Guid.NewGuid(),
            KeycloakId = input.KeycloakId,
            Username = input.Username,
            Email = input.Email,
            FirstName = input.FirstName,
            LastName = input.LastName,
            IsActive = true,
            TenantId = tenantId,
            CreatedBy = currentUserService.UserId,
            CreatedAt = DateTime.UtcNow
        };

        // Füge Rollen hinzu
        foreach (var role in input.Roles)
        {
            if (Enum.TryParse<RoleType>(role, out var roleType))
            {
                user.AddRole(roleType);
            }
        }

        // Speichere in der Datenbank
        await dbContext.Users.AddAsync(user, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Benutzer {Username} (ID: {UserId}) erfolgreich erstellt", user.Username, user.Id);

        // Erstelle und veröffentliche Domain-Event
        var userCreatedEvent = new UserCreatedEvent(user);
        await eventBus.PublishAsync(userCreatedEvent, cancellationToken);

        // Veröffentliche Subscription-Event
        await eventSender.SendAsync(
            nameof(Subscription.OnUserCreated),
            new UserCreatedNotification
            {
                UserId = user.Id,
                Username = user.Username,
                CreatedBy = user.CreatedBy,
                TenantId = user.TenantId
            },
            cancellationToken);

        return new CreateUserPayload(user)
        {
            User = user
        };
    }

    [GraphQLDescription("Aktualisiert einen Benutzer")]
    public async Task<UpdateUserPayload> UpdateUser(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService,
        [Service] ITopicEventSender eventSender,
        [Service] IEventBus eventBus,
        UpdateUserInput input,
        CancellationToken cancellationToken) {
        logger.LogInformation("Mutation: UpdateUser für ID {UserId}", input.Id);

        // Berechtigungsprüfung
        if (!currentUserService.IsInRole("OmeAdmin") && !currentUserService.IsInRole("OmeSuperUser"))
        {
            logger.LogWarning("Unbefugter Zugriff auf UpdateUser durch Benutzer {UserId}",
                currentUserService.UserId);
            throw new UnauthorizedAccessException("Sie haben keine Berechtigung, Benutzer zu aktualisieren.");
        }

        var tenantId = currentUserService.TenantId;

        // Lade den Benutzer aus der Datenbank
        var user = await dbContext.Users
            .Include(u => u.Roles)
            .FirstOrDefaultAsync(u =>
                    u.Id == input.Id && u.TenantId == tenantId && !u.IsDeleted,
                cancellationToken);

        if (user == null)
        {
            logger.LogWarning("Benutzer mit ID {UserId} nicht gefunden", input.Id);
            throw new GraphQLException($"Benutzer mit ID {input.Id} nicht gefunden.");
        }

        // Prüfe, ob der neue Benutzername oder die neue E-Mail bereits existieren
        if (input.Username != user.Username || input.Email != user.Email)
        {
            var existingUser = await dbContext.Users
                .AnyAsync(u =>
                        (u.Username == input.Username || u.Email == input.Email) &&
                        u.Id != input.Id &&
                        u.TenantId == tenantId &&
                        !u.IsDeleted,
                    cancellationToken);

            if (existingUser)
            {
                logger.LogWarning(
                    "Versuch, einen Benutzer auf bereits existierenden Benutzernamen oder E-Mail zu aktualisieren: {Username}, {Email}",
                    input.Username, input.Email);

                throw new GraphQLException(
                    "Ein anderer Benutzer mit diesem Benutzernamen oder dieser E-Mail existiert bereits.");
            }
        }

        // Aktualisiere den Benutzer
        user.Username = input.Username;
        user.Email = input.Email;
        user.FirstName = input.FirstName;
        user.LastName = input.LastName;
        user.IsActive = input.IsActive;
        user.LastModifiedBy = currentUserService.UserId;
        user.LastModifiedAt = DateTime.UtcNow;

        // Aktualisiere Rollen
        user.Roles.Clear();

        foreach (var role in input.Roles)
        {
            if (Enum.TryParse<RoleType>(role, out var roleType))
            {
                user.AddRole(roleType);
            }
        }

        // Speichere in der Datenbank
        dbContext.Users.Update(user);
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Benutzer {Username} (ID: {UserId}) erfolgreich aktualisiert", user.Username,
            user.Id);

        // Erstelle und veröffentliche Domain-Event
        var userUpdatedEvent = new UserUpdatedEvent(user);
        await eventBus.PublishAsync(userUpdatedEvent, cancellationToken);

        // Veröffentliche Subscription-Event
        await eventSender.SendAsync(
            nameof(Subscription.OnUserUpdated),
            new UserUpdatedNotification
            {
                UserId = user.Id,
                Username = user.Username,
                UpdatedBy = user.LastModifiedBy,
                TenantId = user.TenantId
            },
            cancellationToken);

        return new UpdateUserPayload
        {
            User = user
        };
    }

    [GraphQLDescription("Löscht einen Benutzer")]
    public async Task<DeleteUserPayload> DeleteUser(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService,
        [Service] ITopicEventSender eventSender,
        [Service] IEventBus eventBus,
        DeleteUserInput input,
        CancellationToken cancellationToken) {
        logger.LogInformation("Mutation: DeleteUser für ID {UserId}", input.Id);

        // Berechtigungsprüfung
        if (!currentUserService.IsInRole("OmeAdmin") && !currentUserService.IsInRole("OmeSuperUser"))
        {
            logger.LogWarning("Unbefugter Zugriff auf DeleteUser durch Benutzer {UserId}",
                currentUserService.UserId);
            throw new UnauthorizedAccessException("Sie haben keine Berechtigung, Benutzer zu löschen.");
        }

        var tenantId = currentUserService.TenantId;

        // Lade den Benutzer aus der Datenbank
        var user = await dbContext.Users
            .FirstOrDefaultAsync(u =>
                    u.Id == input.Id && u.TenantId == tenantId && !u.IsDeleted,
                cancellationToken);

        if (user == null)
        {
            logger.LogWarning("Benutzer mit ID {UserId} nicht gefunden", input.Id);
            throw new GraphQLException($"Benutzer mit ID {input.Id} nicht gefunden.");
        }

        // Führe Soft-Delete durch
        user.IsDeleted = true;
        user.LastModifiedBy = currentUserService.UserId;
        user.LastModifiedAt = DateTime.UtcNow;

        // Speichere in der Datenbank
        dbContext.Users.Update(user);
        await dbContext.SaveChangesAsync(cancellationToken);

        logger.LogInformation("Benutzer {Username} (ID: {UserId}) erfolgreich gelöscht", user.Username, user.Id);

        // Erstelle und veröffentliche Domain-Event
        var userDeletedEvent = new UserDeletedEvent(user);
        await eventBus.PublishAsync(userDeletedEvent, cancellationToken);

        // Veröffentliche Subscription-Event
        await eventSender.SendAsync(
            nameof(Subscription.OnUserDeleted),
            new UserDeletedNotification
            {
                UserId = user.Id,
                Username = user.Username,
                DeletedBy = user.LastModifiedBy,
                TenantId = user.TenantId
            },
            cancellationToken);

        return new DeleteUserPayload
        {
            Id = user.Id,
            Success = true
        };
    }
}

// Input/Output-Typen für User-Mutationen

public class CreateUserInput {
    [GraphQLDescription("Die Keycloak-ID des Benutzers")]
    public string KeycloakId { get; set; } = null!;

    [GraphQLDescription("Der Benutzername")]
    public string Username { get; set; } = null!;

    [GraphQLDescription("Die E-Mail-Adresse des Benutzers")]
    public string Email { get; set; } = null!;

    [GraphQLDescription("Der Vorname des Benutzers")]
    public string FirstName { get; set; } = null!;

    [GraphQLDescription("Der Nachname des Benutzers")]
    public string LastName { get; set; } = null!;

    [GraphQLDescription("Die Rollen des Benutzers")]
    public string[] Roles { get; set; } = [];
}

public class CreateUserPayload(User user) {

    [GraphQLDescription("Der erstellte Benutzer")]
    public User User { get; set; } = user;
}

public class UpdateUserInput {
    [GraphQLDescription("Die ID des zu aktualisierenden Benutzers")]
    public Guid Id { get; set; }

    [GraphQLDescription("Der Benutzername")]
    public string Username { get; set; } = null!;

    [GraphQLDescription("Die E-Mail-Adresse des Benutzers")]
    public string Email { get; set; } = null!;

    [GraphQLDescription("Der Vorname des Benutzers")]
    public string FirstName { get; set; } = null!;

    [GraphQLDescription("Der Nachname des Benutzers")]
    public string LastName { get; set; } = null!;

    [GraphQLDescription("Gibt an, ob der Benutzer aktiv ist")]
    public bool IsActive { get; set; }

    [GraphQLDescription("Die Rollen des Benutzers")]
    public string[] Roles { get; set; } = [];
}

public class UpdateUserPayload {
    [GraphQLDescription("Der aktualisierte Benutzer")]
    public User User { get; set; } = null!;
}

public class DeleteUserInput {
    [GraphQLDescription("Die ID des zu löschenden Benutzers")]
    public Guid Id { get; set; }
}

public class DeleteUserPayload {
    [GraphQLDescription("Die ID des gelöschten Benutzers")]
    public Guid Id { get; set; }

    [GraphQLDescription("Gibt an, ob das Löschen erfolgreich war")]
    public bool Success { get; set; }
}