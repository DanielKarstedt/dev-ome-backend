using ome.Core.Domain.Entities.Common;
using ome.Core.Domain.Entities.Users;

namespace ome.Core.Domain.Events.Users;

/// <summary>
/// Event, das ausgelöst wird, wenn ein Benutzer gelöscht wurde
/// </summary>
public class UserDeletedEvent: DomainEvent {
    public Guid UserId { get; }
    public string Username { get; }
    public string DeletedBy { get; }
    public Guid TenantId { get; }

    public UserDeletedEvent(User user) {
        UserId = user.Id;
        Username = user.Username;
        DeletedBy = user.LastModifiedBy;
        TenantId = user.TenantId;
    }
}