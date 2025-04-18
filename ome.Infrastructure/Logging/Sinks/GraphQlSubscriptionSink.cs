using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using Serilog.Core;
using Serilog.Events;

namespace ome.Infrastructure.Logging.Sinks;

/// <summary>
    /// Ein Serilog-Sink, der Log-Ereignisse über GraphQL-Subscriptions verteilt
    /// </summary>
    public class GraphQlSubscriptionSink(
        IFormatProvider formatProvider,
        ILogger<GraphQlSubscriptionSink> logger,
        GraphQlSubscriptionSinkOptions optionsValue)
        : ILogEventSink, IDisposable {
        private readonly ConcurrentDictionary<Guid, ConcurrentQueue<LogEvent>> _tenantLogQueues = new ConcurrentDictionary<Guid, ConcurrentQueue<LogEvent>>();
        private readonly IFormatProvider _formatProvider = formatProvider;
        private readonly GraphQlSubscriptionSinkOptions _options = optionsValue;
        
        public void Emit(LogEvent logEvent)
        {
            try
            {
                // Prüfen, ob das Log-Event eine TenantId hat
                if (!logEvent.Properties.TryGetValue("TenantId", out var tenantIdProperty) ||
                    tenantIdProperty is not ScalarValue { Value: string tenantIdString } ||
                    !Guid.TryParse(tenantIdString, out var tenantId))
                {
                    return;
                }

                // Wenn die TenantId gültig ist, füge das Log-Event in die entsprechende Queue ein
                var queue = _tenantLogQueues.GetOrAdd(tenantId, _ => new ConcurrentQueue<LogEvent>());
                queue.Enqueue(logEvent);
                    
                // In einem echten System würden wir hier das Event asynchron über den GraphQL-Subscription-Mechanismus publizieren
                // PublishLogEventAsync(tenantId, logEvent);
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Fehler beim Emittieren eines Log-Events über GraphQL-Subscription");
            }
        }

        /// <summary>
        /// Ruft die neuesten Log-Einträge für einen bestimmten Tenant ab
        /// </summary>
        public Task<LogEvent[]> GetLatestLogsForTenantAsync(Guid tenantId, int maxCount = 100)
        {
            if (!_tenantLogQueues.TryGetValue(tenantId, out var queue))
            {
                return Task.FromResult(Array.Empty<LogEvent>());
            }

            var logs = new LogEvent[Math.Min(queue.Count, maxCount)];
                
            for (var i = 0; i < logs.Length; i++)
            {
                if (queue.TryDequeue(out var logEvent))
                {
                    logs[i] = logEvent;
                }
            }
                
            return Task.FromResult(logs);

        }

        /// <summary>
        /// Bereinigt alte Log-Einträge, um Speicherverbrauch zu begrenzen
        /// </summary>
        public void Cleanup(TimeSpan olderThan)
        {
            var now = DateTimeOffset.UtcNow;
            
            foreach (var tenantId in _tenantLogQueues.Keys)
            {
                if (!_tenantLogQueues.TryGetValue(tenantId, out var queue))
                {
                    continue;
                }

                var newQueue = new ConcurrentQueue<LogEvent>();
                    
                while (queue.TryDequeue(out var logEvent))
                {
                    // Behalte nur neuere Events
                    if (now - logEvent.Timestamp < olderThan)
                    {
                        newQueue.Enqueue(logEvent);
                    }
                }
                    
                _tenantLogQueues[tenantId] = newQueue;
            }
        }

       public void Dispose()
        {
            _tenantLogQueues.Clear();
        }
    }