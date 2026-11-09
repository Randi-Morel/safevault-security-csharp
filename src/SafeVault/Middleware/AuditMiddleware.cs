using System.Diagnostics;

namespace SafeVault.Middleware;

public sealed class AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger)
{
    public async Task InvokeAsync(HttpContext context)
    {
        var timer = Stopwatch.StartNew();
        try { await next(context); }
        finally
        {
            // Solo el patrón de ruta, nunca cuerpos, query strings, Authorization ni contraseñas.
            var route = (context.GetEndpoint() as RouteEndpoint)?.RoutePattern.RawText ?? "unmatched";
            logger.LogInformation("{Method} {Route} -> {Status} ({Ms}ms), RequestId={Id}",
                context.Request.Method, route, context.Response.StatusCode, timer.ElapsedMilliseconds, context.TraceIdentifier);
        }
    }
}
