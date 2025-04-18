using ome.Core.Domain.Entities.Common;
using ome.Core.Interfaces.Messaging;


namespace ome.API.Extensions;
    /// <summary>
    /// In-Memory-Implementierung des Event Bus
    /// </summary>
    public class InMemoryEventBus : IEventBus
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<InMemoryEventBus> _logger;
        
        public InMemoryEventBus(
            IServiceProvider serviceProvider,
            ILogger<InMemoryEventBus> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }
        
        /// <summary>
        /// Veröffentlicht ein Event an alle registrierten Handler
        /// </summary>
        public async Task PublishAsync<TEvent>(TEvent @event, CancellationToken cancellationToken = default) 
            where TEvent : IDomainEvent
        {
            _logger.LogDebug("Veröffentliche Event {EventType} mit ID {EventId}", typeof(TEvent).Name, @event.Id);
            
            try
            {
                // Hole alle Handler für diesen Event-Typ
                using var scope = _serviceProvider.CreateScope();
                var handlerType = typeof(IDomainEventHandler<>).MakeGenericType(typeof(TEvent));
                var handlers = scope.ServiceProvider.GetServices(handlerType);
                
                // Führe alle Handler aus
                var tasks = new List<Task>();
                
                foreach (var handler in handlers)
                {
                    _logger.LogDebug("Führe Handler {HandlerType} für Event {EventType} aus", 
                        handler?.GetType().Name, typeof(TEvent).Name);
                        
                    var method = handlerType.GetMethod("HandleAsync");
                    var task = (Task)method!.Invoke(handler, [@event, cancellationToken])!;
                    tasks.Add(task);
                }
                
                // Warte auf alle Handler
                await Task.WhenAll(tasks);
                
                _logger.LogDebug("Event {EventType} mit ID {EventId} erfolgreich verarbeitet", 
                    typeof(TEvent).Name, @event.Id);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Fehler beim Veröffentlichen von Event {EventType} mit ID {EventId}", 
                    typeof(TEvent).Name, @event.Id);
                throw;
            }
        }
    }