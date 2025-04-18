using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using ome.Core.Domain.Entities.Common;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Persistence.Interceptors;

public class AuditSaveChangesInterceptor(IServiceProvider serviceProvider): SaveChangesInterceptor {
    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result) {
        UpdateEntities(eventData.Context!);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default) {
        UpdateEntities(eventData.Context!);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private void UpdateEntities(DbContext? context) {
        if (context == null) return;

        using var scope = serviceProvider.CreateScope();
        var currentUserService = scope.ServiceProvider.GetRequiredService<ICurrentUserService>();

        var userId = currentUserService.UserId;
        var now = DateTime.UtcNow;

        foreach (var entry in context.ChangeTracker.Entries<BaseEntity>())
        {
            switch (entry.State)
            {
                case EntityState.Added:
                    entry.Entity.CreatedAt = now;
                    entry.Entity.CreatedBy = userId;
                    break;
                case EntityState.Modified or EntityState.Deleted: {
                    entry.Entity.LastModifiedAt = now;
                    entry.Entity.LastModifiedBy = userId;

                    if (entry.State != EntityState.Deleted)
                    {
                        continue;
                    }

                    entry.State = EntityState.Modified;
                    entry.Entity.IsDeleted = true;
                    break;
                }
            }
        }
    }
}