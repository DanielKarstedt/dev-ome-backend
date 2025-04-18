using ome.Core.Domain.Entities.Common;

namespace ome.Core.Interfaces.Messaging;

/// <summary>
/// Interface für den Event Bus
/// </summary>
public interface IEventBus {
    Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default)
        where TEvent : IDomainEvent;
}