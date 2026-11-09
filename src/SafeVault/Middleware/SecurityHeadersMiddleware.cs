namespace SafeVault.Middleware;

public sealed class SecurityHeadersMiddleware(RequestDelegate next)
{
    public Task InvokeAsync(HttpContext context)
    {
        // OnStarting conserva las cabeceras incluso si el manejador de errores limpia la respuesta.
        context.Response.OnStarting(() =>
        {
            context.Response.Headers.ContentSecurityPolicy = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
            context.Response.Headers.XContentTypeOptions = "nosniff";
            context.Response.Headers.XFrameOptions = "DENY";
            context.Response.Headers["Referrer-Policy"] = "no-referrer";
            context.Response.Headers.CacheControl = "no-store";
            context.Response.Headers["X-Request-Id"] = context.TraceIdentifier;
            return Task.CompletedTask;
        });
        return next(context);
    }
}
