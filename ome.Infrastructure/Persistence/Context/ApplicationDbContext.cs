using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Common;
using ome.Core.Domain.Entities.Tenants;
using ome.Core.Domain.Entities.Users;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Persistence.Context;

public class ApplicationDbContext(
    DbContextOptions<ApplicationDbContext> options,
    ICurrentUserService? currentUserService = null,
    ITenantService? tenantService = null,
    ILogger<ApplicationDbContext>? logger = null)
    : DbContext(options) {
    private readonly ICurrentUserService? _currentUserService = currentUserService;

    // DbSets
    public DbSet<User> Users { get; set; }
    public DbSet<UserRole> UserRoles { get; set; }
    public DbSet<Tenant> Tenants { get; set; }

    // Ein einziger Konstruktor mit optionalen Parametern

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        // Apply entity configurations from the assembly
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(ApplicationDbContext).Assembly);

        // Apply tenant filtering for multi-tenant entities only if _tenantService is available
        if (tenantService != null)
        {
            foreach (var entityType in modelBuilder.Model.GetEntityTypes()
                         .Where(e => typeof(TenantEntity).IsAssignableFrom(e.ClrType)))
            {
                var method = typeof(ApplicationDbContext)
                    .GetMethod(nameof(ApplyTenantFilter), 
                        System.Reflection.BindingFlags.NonPublic | 
                        System.Reflection.BindingFlags.Instance);

                if (method == null) {
                    continue;
                }

                var genericMethod = method.MakeGenericMethod(entityType.ClrType);
                genericMethod.Invoke(this, [modelBuilder]);
            }
        }

        // Apply soft delete filtering for base entities
        foreach (var entityType in modelBuilder.Model.GetEntityTypes()
                     .Where(e => typeof(BaseEntity).IsAssignableFrom(e.ClrType)))
        {
            var method = typeof(ApplicationDbContext)
                .GetMethod(nameof(ApplySoftDeleteFilter), 
                    System.Reflection.BindingFlags.NonPublic | 
                    System.Reflection.BindingFlags.Instance);

            if (method == null) {
                continue;
            }

            var genericMethod = method.MakeGenericMethod(entityType.ClrType);
            genericMethod.Invoke(this, [modelBuilder]);
        }
    }

    // Private method to apply tenant filter
    private void ApplyTenantFilter<T>(ModelBuilder modelBuilder) where T : TenantEntity
    {
        try 
        {
            // Null-Check für _tenantService
            if (tenantService == null)
            {
                // Wenn kein TenantService verfügbar ist, nur IsDeleted-Filter anwenden
                modelBuilder.Entity<T>().HasQueryFilter(e => !e.IsDeleted);
                return;
            }

            // Try to get tenant ID from tenant service
            var tenantId = tenantService.GetCurrentTenantId();

            modelBuilder.Entity<T>().HasQueryFilter(e => 
                !e.IsDeleted && 
                (tenantId == Guid.Empty || e.TenantId == tenantId)
            );
        }
        catch (Exception ex)
        {
            // Null-Check für _logger
            logger?.LogError(ex, "Error applying tenant filter");
        }
    }

    // Private method to apply soft delete filter
    private void ApplySoftDeleteFilter<T>(ModelBuilder modelBuilder) where T : BaseEntity
    {
        modelBuilder.Entity<T>().HasQueryFilter(e => !e.IsDeleted);
    }

    // Override SaveChanges to set tenant ID for new entities
    public override int SaveChanges()
    {
        try {
            // Null-Check für _tenantService
            if (tenantService != null)
            {
                var tenantId = tenantService.GetCurrentTenantId();

                foreach (var entry in ChangeTracker.Entries<TenantEntity>())
                {
                    if (entry.State == EntityState.Added && entry.Entity.TenantId == Guid.Empty)
                    {
                        entry.Entity.TenantId = tenantId;
                    }
                }
            }

            return base.SaveChanges();
        }
        catch (Exception ex)
        {
            // Null-Check für _logger
            logger?.LogError(ex, "Error during SaveChanges");
            throw;
        }
    }

    // Async version of SaveChanges
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        try 
        {
            // Null-Check für _tenantService
            if (tenantService != null)
            {
                var tenantId = tenantService.GetCurrentTenantId();

                foreach (var entry in ChangeTracker.Entries<TenantEntity>())
                {
                    if (entry.State == EntityState.Added && entry.Entity.TenantId == Guid.Empty)
                    {
                        entry.Entity.TenantId = tenantId;
                    }
                }
            }

            return await base.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            // Null-Check für _logger
            logger?.LogError(ex, "Error during SaveChangesAsync");
            throw;
        }
    }
}