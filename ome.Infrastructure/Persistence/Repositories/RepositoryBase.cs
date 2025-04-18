using System.Linq.Expressions;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Common;
using ome.Core.Interfaces.Persistence;
using ome.Infrastructure.Persistence.Context;

namespace ome.Infrastructure.Persistence.Repositories;

public class RepositoryBase<T>(ApplicationDbContext dbContext, ILogger<RepositoryBase<T>> logger)
    : IRepository<T>
    where T : BaseEntity {

    public async Task<T> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) {
        logger.LogDebug("Getting entity {EntityType} with ID {EntityId}", typeof(T).Name, id);
        return (await dbContext.Set<T>().FindAsync([id], cancellationToken))!;
    }

    public async Task<IReadOnlyList<T>> ListAllAsync(CancellationToken cancellationToken = default) {
        logger.LogDebug("Getting all entities of type {EntityType}", typeof(T).Name);
        return await dbContext.Set<T>().ToListAsync(cancellationToken);
    }

    public async Task<IReadOnlyList<T>> ListAsync(Expression<Func<T, bool>> predicate,
        CancellationToken cancellationToken = default) {
        logger.LogDebug("Getting entities of type {EntityType} with predicate", typeof(T).Name);
        return await dbContext.Set<T>().Where(predicate).ToListAsync(cancellationToken);
    }

    public async Task<T> AddAsync(T entity, CancellationToken cancellationToken = default) {
        logger.LogDebug("Adding entity of type {EntityType}", typeof(T).Name);
        await dbContext.Set<T>().AddAsync(entity, cancellationToken);
        await dbContext.SaveChangesAsync(cancellationToken);
        return entity;
    }

    public async Task UpdateAsync(T entity, CancellationToken cancellationToken = default) {
        logger.LogDebug("Updating entity of type {EntityType} with ID {EntityId}", typeof(T).Name, entity.Id);
        dbContext.Entry(entity).State = EntityState.Modified;
        await dbContext.SaveChangesAsync(cancellationToken);
    }

    public async Task DeleteAsync(T entity, CancellationToken cancellationToken = default) {
        logger.LogDebug("Deleting entity of type {EntityType} with ID {EntityId}", typeof(T).Name, entity.Id);
        // Soft-Delete wird durch den Interceptor umgesetzt
        dbContext.Set<T>().Remove(entity);
        await dbContext.SaveChangesAsync(cancellationToken);
    }
}