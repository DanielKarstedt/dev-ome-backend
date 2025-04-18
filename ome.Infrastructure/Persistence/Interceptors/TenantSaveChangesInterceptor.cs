using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;
using ome.Core.Domain.Entities.Common;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Persistence.Interceptors;

public class TenantSaveChangesInterceptor(ITenantService tenantService): SaveChangesInterceptor {

    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result) {
        SetTenantIds(eventData.Context!);
        return base.SavingChanges(eventData, result);
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default) {
        SetTenantIds(eventData.Context);
        return base.SavingChangesAsync(eventData, result, cancellationToken);
    }

    private void SetTenantIds(DbContext? context) {
        if (context == null) return;

        var tenantId = tenantService.GetCurrentTenantId();

        foreach (var entry in context.ChangeTracker.Entries<TenantEntity>())
        {
            if (entry.State == EntityState.Added)
            {
                entry.Entity.TenantId = tenantId;
            }
        }
    }
}