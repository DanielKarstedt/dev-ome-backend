namespace ome.Core.Domain.Entities.Common;

/// <summary>
/// Basisklasse für alle Domain-Events
/// </summary>
public class DomainEvent: IDomainEvent {
    public Guid Id { get; } = Guid.NewGuid();
    public DateTime OccurredOn { get; } = DateTime.UtcNow;
}