using System.Linq.Expressions;
using ome.Core.Domain.Entities.Common;

namespace ome.Core.Interfaces.Persistence;

/// <summary>
/// Generisches Repository-Interface für Datenbankzugriffe
/// </summary>
public interface IRepository<T> where T : BaseEntity {
    Task<T> GetByIdAsync(Guid id, CancellationToken cancellationToken = default);
    Task<IReadOnlyList<T>> ListAllAsync(CancellationToken cancellationToken = default);

    Task<IReadOnlyList<T>> ListAsync(Expression<Func<T, bool>> predicate,
        CancellationToken cancellationToken = default);

    Task<T> AddAsync(T entity, CancellationToken cancellationToken = default);
    Task UpdateAsync(T entity, CancellationToken cancellationToken = default);
    Task DeleteAsync(T entity, CancellationToken cancellationToken = default);
}