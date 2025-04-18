using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using ome.Core.Domain.Entities.Users;

namespace ome.Infrastructure.Persistence.Configurations;

public class UserRoleConfiguration: IEntityTypeConfiguration<UserRole> {
    public void Configure(EntityTypeBuilder<UserRole> builder) {
        builder.ToTable("UserRoles");

        builder.HasKey(r => r.Id);

        builder.Property(r => r.RoleName)
            .IsRequired()
            .HasMaxLength(100);

        // Unique Index für UserId, RoleName und TenantId
        builder.HasIndex(r => new { r.UserId, r.RoleName, r.TenantId })
            .IsUnique();
    }
}