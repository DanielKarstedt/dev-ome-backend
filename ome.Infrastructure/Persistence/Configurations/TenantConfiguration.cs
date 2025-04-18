using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using ome.Core.Domain.Entities.Tenants;

namespace ome.Infrastructure.Persistence.Configurations;

public class TenantConfiguration: IEntityTypeConfiguration<Tenant> {
    public void Configure(EntityTypeBuilder<Tenant> builder) {
        builder.ToTable("Tenants");

        builder.HasKey(t => t.Id);

        builder.Property(t => t.Name)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(t => t.DisplayName)
            .IsRequired()
            .HasMaxLength(200);

        builder.Property(t => t.KeycloakGroupId)
            .IsRequired()
            .HasMaxLength(100);

        builder.Property(t => t.ConnectionString)
            .HasMaxLength(500);

        builder.Property(t => t.IsActive)
            .IsRequired();

        // Unique Index für Name
        builder.HasIndex(t => t.Name)
            .IsUnique();

        // Unique Index für KeycloakGroupId
        builder.HasIndex(t => t.KeycloakGroupId)
            .IsUnique();
    }
}