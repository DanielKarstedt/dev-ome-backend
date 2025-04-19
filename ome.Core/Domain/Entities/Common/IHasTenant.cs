namespace ome.Core.Domain.Entities.Common;

public interface IHasTenant
{
    Guid TenantId { get; set; }
}
