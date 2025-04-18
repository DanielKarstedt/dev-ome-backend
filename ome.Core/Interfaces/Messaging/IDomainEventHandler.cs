using ome.Core.Domain.Entities.Common;

namespace ome.Core.Interfaces.Messaging;

/// <summary>
/// Interface für Handler von Domain-Events
/// </summary>
public interface IDomainEventHandler<in TEvent> where TEvent : IDomainEvent {
    Task HandleAsync(TEvent @event, CancellationToken cancellationToken = default);
}