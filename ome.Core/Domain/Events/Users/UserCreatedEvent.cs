using ome.Core.Domain.Entities.Common;
using ome.Core.Domain.Entities.Users;

namespace ome.Core.Domain.Events.Users;

/// <summary>
/// Event, das ausgelöst wird, wenn ein Benutzer erstellt wurde
/// </summary>
public class UserCreatedEvent: DomainEvent {
    public Guid UserId { get; }
    public string Username { get; }
    public string CreatedBy { get; }
    public Guid TenantId { get; }

    public UserCreatedEvent(User user) {
        UserId = user.Id;
        Username = user.Username;
        CreatedBy = user.CreatedBy;
        TenantId = user.TenantId;
    }
}