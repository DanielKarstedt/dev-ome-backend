using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Common;
using ome.Core.Interfaces.Persistence;
using ome.Core.Interfaces.Services;
using ome.Infrastructure.Persistence.Context;

namespace ome.Infrastructure.Persistence.Repositories;

public class TenantRepositoryBase<T>(
    ApplicationDbContext dbContext,
    ITenantService tenantService,
    ILogger<TenantRepositoryBase<T>> logger)
    : ITenantRepository<T>
    where T : TenantEntity {
    protected readonly ApplicationDbContext DbContext = dbContext;
    protected readonly ILogger<TenantRepositoryBase<T>> Logger = logger;

    public async Task<T> GetByIdAsync(Guid id, Guid tenantId, CancellationToken cancellationToken = default) {
        Logger.LogDebug("Getting entity {EntityType} with ID {EntityId} for tenant {TenantId}",
            typeof(T).Name, id, tenantId);

        return (await DbContext.Set<T>()
            .Where(e => e.Id == id && e.TenantId == tenantId && !e.IsDeleted)
            .FirstOrDefaultAsync(cancellationToken))!;
    }

    public async Task<IReadOnlyList<T>>
        ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken = default) {
        Logger.LogDebug("Getting all entities of type {EntityType} for tenant {TenantId}",
            typeof(T).Name, tenantId);

        return await DbContext.Set<T>()
            .Where(e => e.TenantId == tenantId && !e.IsDeleted)
            .ToListAsync(cancellationToken);
    }

    public async Task<T> AddAsync(T entity, CancellationToken cancellationToken = default) {
        Logger.LogDebug("Adding entity of type {EntityType} for tenant {TenantId}",
            typeof(T).Name, entity.TenantId);

        entity.TenantId = tenantService.GetCurrentTenantId();
        await DbContext.Set<T>().AddAsync(entity, cancellationToken);
        await DbContext.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public async Task UpdateAsync(T entity, CancellationToken cancellationToken = default) {
        Logger.LogDebug("Updating entity of type {EntityType} with ID {EntityId} for tenant {TenantId}",
            typeof(T).Name, entity.Id, entity.TenantId);

        // Sicherstellen, dass die TenantId nicht geändert wird
        var currentTenantId = tenantService.GetCurrentTenantId();

        if (entity.TenantId != currentTenantId)
        {
            Logger.LogWarning("Attempted to update entity {EntityType} with ID {EntityId} for different tenant",
                typeof(T).Name, entity.Id);
            throw new UnauthorizedAccessException("Cannot update entity for different tenant");
        }

        DbContext.Entry(entity).State = EntityState.Modified;
        await DbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteAsync(T entity, CancellationToken cancellationToken = default) {
        Logger.LogDebug("Deleting entity of type {EntityType} with ID {EntityId} for tenant {TenantId}",
            typeof(T).Name, entity.Id, entity.TenantId);

        // Sicherstellen, dass die TenantId zur aktuellen Tenant gehört
        var currentTenantId = tenantService.GetCurrentTenantId();

        if (entity.TenantId != currentTenantId)
        {
            Logger.LogWarning("Attempted to delete entity {EntityType} with ID {EntityId} for different tenant",
                typeof(T).Name, entity.Id);
            throw new UnauthorizedAccessException("Cannot delete entity for different tenant");
        }

        // Soft-Delete wird durch den Interceptor umgesetzt
        DbContext.Set<T>().Remove(entity);
        await DbContext.SaveChangesAsync(cancellationToken);
    }
}