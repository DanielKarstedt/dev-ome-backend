using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using ome.Core.Domain.Entities.Tenants;
using ome.Core.Domain.Entities.Users;
using ome.Core.Interfaces.Services;

namespace ome.Infrastructure.Persistence.Context {
    public class ApplicationDbContext : DbContext {
        private readonly ITenantService _tenantService;
        private readonly ILogger<ApplicationDbContext> _logger;
        private readonly Guid _currentTenantId;

        public ApplicationDbContext(
            DbContextOptions<ApplicationDbContext> options,
            ITenantService tenantService,
            ILogger<ApplicationDbContext> logger) : base(options) {
            _tenantService = tenantService;
            _logger = logger;

            // Tenant-ID beim Erstellen des Kontexts abrufen
            _currentTenantId = _tenantService.GetCurrentTenantId();

            if (_currentTenantId != Guid.Empty) {
                _logger.LogDebug("DbContext für Tenant {TenantId} erstellt", _currentTenantId);
            }
        }

        public DbSet<Tenant> Tenants { get; set; } = null!;
        public DbSet<User> Users { get; set; } = null!;
        public DbSet<UserRole> UserRoles { get; set; } = null!;
        // Weitere DbSets für andere Entitäten...


        protected override void OnModelCreating(ModelBuilder modelBuilder) {
            base.OnModelCreating(modelBuilder);

            // Konfiguriere Entities
            modelBuilder.Entity<Tenant>(builder => {
                builder.ToTable("Tenants");
                builder.HasKey(t => t.Id);
                builder.Property(t => t.Name).IsRequired().HasMaxLength(100);
                builder.Property(t => t.DisplayName).IsRequired().HasMaxLength(200);
                builder.Property(t => t.ConnectionString).HasMaxLength(500);
            });

            modelBuilder.Entity<User>(builder => {
                builder.ToTable("Users");
                builder.HasKey(u => u.Id);
                builder.Property(u => u.Username).IsRequired().HasMaxLength(100);
                builder.Property(u => u.Email).IsRequired().HasMaxLength(200);
                builder.Property(u => u.TenantId).IsRequired();

                // Multi-Tenant-Filter für Benutzer
                builder.HasQueryFilter(u => u.TenantId == _currentTenantId || _currentTenantId == Guid.Empty);
            });
            
            modelBuilder.Entity<UserRole>(builder =>
            {
                builder.ToTable("UserRoles");
                builder.HasKey(ur => ur.Id);
                
                // Konfiguration der Eigenschaften
                builder.Property(ur => ur.UserId).IsRequired();
                builder.Property(ur => ur.RoleName).IsRequired().HasMaxLength(100);
                builder.Property(ur => ur.TenantId).IsRequired();
                
                builder.Ignore("UserId1");

        
                // Beziehung zum Benutzer definieren
                builder.HasOne(ur => ur.User)
                    .WithMany(u => u.Roles)
                    .HasForeignKey(ur => ur.UserId)
                    .OnDelete(DeleteBehavior.Cascade);
            
                // Multi-Tenant-Filter
                builder.HasQueryFilter(ur => ur.TenantId == _currentTenantId || _currentTenantId == Guid.Empty);
            });

            // Multi-Tenant-Filter für andere Entitäten (Beispiel)
            // modelBuilder.Entity<Document>(builder =>
            // {
            //     builder.ToTable("Documents");
            //     builder.HasKey(d => d.Id);
            //     builder.Property(d => d.TenantId).IsRequired();
            //     
            //     // Multi-Tenant-Filter
            //     builder.HasQueryFilter(d => d.TenantId == _currentTenantId || _currentTenantId == Guid.Empty);
            // });

            // Weitere Entitäten hier konfigurieren...
        }

        /// <summary>
        /// Überschreibt SaveChanges, um TenantId automatisch zu setzen
        /// </summary>
        public override int SaveChanges() {
            SetTenantIdForNewEntities();
            return base.SaveChanges();
        }

        /// <summary>
        /// Überschreibt SaveChangesAsync, um TenantId automatisch zu setzen
        /// </summary>
        public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) {
            SetTenantIdForNewEntities();
            return base.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Setzt TenantId für neue Entitäten, die IHasTenant implementieren
        /// </summary>
        private void SetTenantIdForNewEntities() {
            var tenantId = _currentTenantId;

            if (tenantId == Guid.Empty) {
                // Versuche, die Tenant-ID vom Service zu bekommen
                tenantId = _tenantService.GetCurrentTenantId();
            }

            if (tenantId == Guid.Empty) {
                _logger.LogWarning("Keine aktive Tenant-ID gefunden beim Speichern von Änderungen");
                return;
            }

            // Finde alle neuen Entitäten, die IHasTenant implementieren
            var entities = ChangeTracker.Entries()
                .Where(e => e is { State: EntityState.Added, Entity: IHasTenant })
                .Select(e => e.Entity as IHasTenant)
                .ToList();

            foreach (var entity in entities.Where(entity => entity!.TenantId == Guid.Empty)) {
                entity!.TenantId = tenantId;

                _logger.LogTrace("TenantId {TenantId} automatisch für {EntityType} gesetzt",
                    tenantId, entity.GetType().Name);
            }
        }
    }

    /// <summary>
    /// Interface für Entitäten, die einem Tenant zugeordnet sind
    /// </summary>
    public interface IHasTenant {
        Guid TenantId { get; set; }
    }
}