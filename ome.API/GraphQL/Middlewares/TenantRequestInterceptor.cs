using HotChocolate.AspNetCore;
using HotChocolate.Execution;
using ome.Core.Interfaces.Services;

namespace ome.API.GraphQL.Middlewares;

public class TenantHttpRequestInterceptor(IServiceProvider serviceProvider): DefaultHttpRequestInterceptor {

    public override ValueTask OnCreateAsync(
        HttpContext context,
        IRequestExecutor requestExecutor,
        OperationRequestBuilder requestBuilder,
        CancellationToken cancellationToken)
    {
        // IServiceScope erstellen, um den scoped Service aufzulösen
        using var scope = serviceProvider.CreateScope();
        var tenantService = scope.ServiceProvider.GetRequiredService<ITenantService>();

        // Extrahiere Tenant-ID aus dem HTTP-Context
        var tenantId = tenantService.GetCurrentTenantId();

        // Füge die Tenant-ID als globale State-Variable hinzu
        if (tenantId != Guid.Empty)
        {
            requestBuilder.SetGlobalState("tenantId", tenantId);
        }

        return base.OnCreateAsync(context, requestExecutor, requestBuilder, cancellationToken);
    }
}