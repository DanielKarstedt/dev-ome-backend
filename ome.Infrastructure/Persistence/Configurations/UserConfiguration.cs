using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using ome.Core.Domain.Entities.Users;

namespace ome.Infrastructure.Persistence.Configurations;

public class UserConfiguration: IEntityTypeConfiguration<User> {
    public void Configure(EntityTypeBuilder<User> builder) {
        builder.ToTable("Users");

        builder.HasKey(u => u.Id);

        builder.Property(u => u.KeycloakId)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(u => u.Username)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(u => u.Email)
            .IsRequired()
            .HasMaxLength(256);

        builder.Property(u => u.FirstName)
            .HasMaxLength(100);

        builder.Property(u => u.LastName)
            .HasMaxLength(100);

        builder.Property(u => u.IsActive)
            .IsRequired();

        // Unique Index für Username pro Tenant
        builder.HasIndex(u => new { u.Username, u.TenantId })
            .IsUnique();

        // Unique Index für Email pro Tenant
        builder.HasIndex(u => new { u.Email, u.TenantId })
            .IsUnique();

        // Unique Index für KeycloakId
        builder.HasIndex(u => u.KeycloakId)
            .IsUnique();

        // Relation zu UserRole
        builder.HasMany(u => u.Roles)
            .WithOne()
            .HasForeignKey(r => r.UserId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}