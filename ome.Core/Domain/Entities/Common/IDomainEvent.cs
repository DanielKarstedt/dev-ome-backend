namespace ome.Core.Domain.Entities.Common;

/// <summary>
/// Interface für alle Domain-Events
/// </summary>
public interface IDomainEvent {
    Guid Id { get; }
    DateTime OccurredOn { get; }
}