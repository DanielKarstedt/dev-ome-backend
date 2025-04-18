using Microsoft.EntityFrameworkCore;
using ome.Core.Domain.Entities.Tenants;
using ome.Core.Domain.Entities.Users;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Persistence.Context;

namespace ome.API.GraphQL.Queries;

/// <summary>
/// GraphQL-Queries für die Anwendung
/// </summary>
[GraphQLDescription("Queries für die MultiTenant-Anwendung")]
public class Query(ILogger<Query> logger) {

    // BENUTZER-QUERIES

    [GraphQLDescription("Gibt einen Benutzer anhand seiner ID zurück")]
    [UseFirstOrDefault]
    [UseProjection]
    [HotChocolate.Data.UseFiltering]
    [HotChocolate.Data.UseSorting]
    public IQueryable<User> GetUserById(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService,
        Guid id) {
        logger.LogInformation("Query: GetUserById für ID {UserId}", id);

        var tenantId = currentUserService.TenantId;

        return dbContext.Users
            .Where(u => u.Id == id && u.TenantId == tenantId)
            .Include(u => u.Roles);
    }

    [GraphQLDescription("Gibt alle Benutzer für den aktuellen Tenant zurück")]
    [UsePaging]
    [UseProjection]
    [HotChocolate.Data.UseFiltering]
    [HotChocolate.Data.UseSorting]
    public IQueryable<User> GetUsers(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService) {
        logger.LogInformation("Query: GetUsers für Tenant {TenantId}", currentUserService.TenantId);

        var tenantId = currentUserService.TenantId;

        return dbContext.Users
            .Where(u => u.TenantId == tenantId)
            .Include(u => u.Roles);
    }

    [GraphQLDescription("Gibt den aktuellen Benutzer zurück")]
    [UseFirstOrDefault]
    [UseProjection]
    [HotChocolate.Data.UseFiltering]
    [HotChocolate.Data.UseSorting]
    public IQueryable<User> GetCurrentUser(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService) {
        logger.LogInformation("Query: GetCurrentUser für Benutzer {UserId}", currentUserService.UserId);

        if (currentUserService.IsAuthenticated)
        {
            return dbContext.Users
                .Where(u => u.KeycloakId == currentUserService.UserId)
                .Include(u => u.Roles);
        }

        logger.LogWarning("Nicht authentifizierter Benutzer versucht, GetCurrentUser abzurufen");
        throw new UnauthorizedAccessException("Sie müssen angemeldet sein, um auf diese Ressource zuzugreifen.");

    }

    // TENANT-QUERIES

    [GraphQLDescription("Gibt den aktuellen Tenant zurück")]
    [UseFirstOrDefault]
    public async Task<Tenant?> GetCurrentTenant(
        [Service] ITenantService tenantService,
        CancellationToken cancellationToken) {
        logger.LogInformation("Query: GetCurrentTenant für Tenant {TenantId}", tenantService.GetCurrentTenantId());

        return await tenantService.GetCurrentTenantAsync(cancellationToken);
    }

    [GraphQLDescription("Gibt einen Tenant anhand seiner ID zurück (nur für Administratoren)")]
    [UseFirstOrDefault]
    public async Task<Tenant> GetTenantById(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService,
        Guid id,
        CancellationToken cancellationToken) {
        logger.LogInformation("Query: GetTenantById für ID {TenantId}", id);

        // Berechtigungsprüfung: Nur Administratoren dürfen auf Tenant-Informationen zugreifen
        if (currentUserService.IsInRole("OmeAdmin"))
        {
            return (await dbContext.Tenants
                .AsNoTracking()
                .FirstOrDefaultAsync(t => t.Id == id && !t.IsDeleted, cancellationToken))!;
        }

        logger.LogWarning("Unbefugter Zugriff auf GetTenantById durch Benutzer {UserId}",
            currentUserService.UserId);

        throw new UnauthorizedAccessException(
            "Sie haben keine Berechtigung, auf Tenant-Informationen zuzugreifen.");

    }

    [GraphQLDescription("Gibt alle Tenants zurück (nur für Administratoren)")]
    [UsePaging]
    [HotChocolate.Data.UseSorting]
    [HotChocolate.Data.UseFiltering]
    public IQueryable<Tenant> GetTenants(
        [Service] ApplicationDbContext dbContext,
        [Service] ICurrentUserService currentUserService) {
        logger.LogInformation("Query: GetTenants durch Benutzer {UserId}", currentUserService.UserId);

        // Berechtigungsprüfung: Nur Administratoren dürfen auf Tenant-Informationen zugreifen
        if (!currentUserService.IsInRole("OmeAdmin"))
        {
            logger.LogWarning("Unbefugter Zugriff auf GetTenants durch Benutzer {UserId}", currentUserService.UserId);

            throw new UnauthorizedAccessException(
                "Sie haben keine Berechtigung, auf Tenant-Informationen zuzugreifen.");
        }

        return dbContext.Tenants
            .Where(t => !t.IsDeleted)
            .AsNoTracking();
    }
}