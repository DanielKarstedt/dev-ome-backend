using ome.Core.Domain.Entities.Common;

namespace ome.Core.Interfaces.Persistence;

/// <summary>
/// Tenant-spezifisches Repository-Interface
/// </summary>
public interface ITenantRepository<T> where T : TenantEntity {
    Task<T> GetByIdAsync(Guid id, Guid tenantId, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<T>> ListForTenantAsync(Guid tenantId, CancellationToken cancellationToken = default);
    Task<T> AddAsync(T entity, CancellationToken cancellationToken = default);
    Task UpdateAsync(T entity, CancellationToken cancellationToken = default);
    Task DeleteAsync(T entity, CancellationToken cancellationToken = default);
}