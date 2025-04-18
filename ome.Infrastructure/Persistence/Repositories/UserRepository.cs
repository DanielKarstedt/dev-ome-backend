using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Users;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Persistence.Context;

namespace ome.Infrastructure.Persistence.Repositories;

public class UserRepository(
    ApplicationDbContext dbContext,
    ITenantService tenantService,
    ILogger<TenantRepositoryBase<User>> logger)
    : TenantRepositoryBase<User>(dbContext, tenantService, logger) {

    public async Task<User> GetByUsernameAsync(string username, Guid tenantId,
        CancellationToken cancellationToken = default) {
        Logger.LogDebug("Getting user by username {Username} for tenant {TenantId}", username, tenantId);

        return (await DbContext.Users
            .Include(u => u.Roles)
            .FirstOrDefaultAsync(u =>
                    u.Username == username &&
                    u.TenantId == tenantId &&
                    !u.IsDeleted,
                cancellationToken))!;
    }

    public async Task<User> GetByEmailAsync(string email, Guid tenantId,
        CancellationToken cancellationToken = default) {
        Logger.LogDebug("Getting user by email {Email} for tenant {TenantId}", email, tenantId);

        return (await DbContext.Users
            .Include(u => u.Roles)
            .FirstOrDefaultAsync(u =>
                    u.Email == email &&
                    u.TenantId == tenantId &&
                    !u.IsDeleted,
                cancellationToken))!;
    }

    public async Task<User> GetByKeycloakIdAsync(string keycloakId, CancellationToken cancellationToken = default) {
        Logger.LogDebug("Getting user by Keycloak ID {KeycloakId}", keycloakId);

        return (await DbContext.Users
            .Include(u => u.Roles)
            .FirstOrDefaultAsync(u =>
                    u.KeycloakId == keycloakId &&
                    !u.IsDeleted,
                cancellationToken))!;
    }
}