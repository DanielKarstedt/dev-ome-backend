using HotChocolate.Resolvers;
using ome.Core.Interfaces.Services;

namespace ome.API.GraphQL.Types;

/// <summary>
/// Eingabe-Typ für die requirePermission-Direktive
/// </summary>
public class RequirePermissionDirective {
    public string[] Permissions { get; set; } = [];
}

/// <summary>
/// GraphQL-Direktive für Berechtigungsprüfungen
/// </summary>
public class RequirePermissionDirectiveType: DirectiveType<RequirePermissionDirective> {
    protected override void Configure(IDirectiveTypeDescriptor<RequirePermissionDirective> descriptor) {
        descriptor.Name("requirePermission");
        descriptor.Location(DirectiveLocation.FieldDefinition);
        descriptor.Description("Erfordert bestimmte Berechtigungen für den Zugriff auf ein Feld");

        descriptor.Use<RequirePermissionMiddleware>();
    }
}

/// <summary>
/// Middleware-Logik für die requirePermission-Direktive
/// </summary>
public class RequirePermissionMiddleware(FieldDelegate next) {

    public async Task InvokeAsync(IMiddlewareContext context, RequirePermissionDirective directive) {
        var currentUserService = context.Service<ICurrentUserService>();

        if (!currentUserService.IsAuthenticated)
        {
            throw new UnauthorizedAccessException(
                "Sie müssen angemeldet sein, um auf diese Ressource zuzugreifen.");
        }

        var hasPermission = directive.Permissions.Any(p => currentUserService.IsInRole(p));

        if (!hasPermission)
        {
            throw new UnauthorizedAccessException(
                "Sie haben nicht die erforderlichen Berechtigungen für diese Operation.");
        }

        await next(context);
    }
}