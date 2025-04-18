using ome.Core.Domain.Entities.Common;
using ome.Core.Domain.Entities.Users;

namespace ome.Core.Domain.Events.Users;

/// <summary>
/// Event, das ausgelöst wird, wenn ein Benutzer aktualisiert wurde
/// </summary>
public class UserUpdatedEvent: DomainEvent {
    public Guid UserId { get; }
    public string Username { get; }
    public string UpdatedBy { get; }
    public Guid TenantId { get; }

    public UserUpdatedEvent(User user) {
        UserId = user.Id;
        Username = user.Username;
        UpdatedBy = user.LastModifiedBy;
        TenantId = user.TenantId;
    }
}