using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Data;
using SafeVault.Middleware;
using SafeVault.Models;
using SafeVault.Security;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16_384);
builder.Services.AddControllers().AddJsonOptions(options =>
    options.JsonSerializerOptions.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow);
builder.Services.AddProblemDetails();
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddSingleton<VaultStore>();
builder.Services.AddSingleton<PasswordService>();
builder.Services.AddAuthentication(TokenAuthenticationHandler.SchemeName)
    .AddScheme<AuthenticationSchemeOptions, TokenAuthenticationHandler>(TokenAuthenticationHandler.SchemeName, _ => { });
builder.Services.AddAuthorization(options => options.FallbackPolicy = new AuthorizationPolicyBuilder()
    .RequireAuthenticatedUser().Build());
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = 429;
    options.AddPolicy("auth", context => RateLimitPartition.GetFixedWindowLimiter(
        context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = Math.Clamp(builder.Configuration.GetValue("RateLimits:AuthPermitLimit", 20), 1, 100),
            Window = TimeSpan.FromMinutes(1),
            QueueLimit = 0
        }));
});

var app = builder.Build();
var store = app.Services.GetRequiredService<VaultStore>();
if (args.Contains("--create-admin"))
{
    // Aprovisionamiento local: no existe endpoint público de elevación de privilegios.
    var request = new RegisterRequest
    {
        Username = Environment.GetEnvironmentVariable("SAFEVAULT_ADMIN_USERNAME") ?? "",
        Email = Environment.GetEnvironmentVariable("SAFEVAULT_ADMIN_EMAIL") ?? "",
        Password = Environment.GetEnvironmentVariable("SAFEVAULT_ADMIN_PASSWORD") ?? ""
    };
    if (!Validator.TryValidateObject(request, new ValidationContext(request), new List<ValidationResult>(), true))
        throw new InvalidOperationException("Define credenciales administrativas válidas en las variables SAFEVAULT_ADMIN_*.");
    var hash = app.Services.GetRequiredService<PasswordService>().Hash(request.Password);
    if (store.CreateAccount(request.Username, request.Email.ToLowerInvariant(), hash, "Admin") is null)
        throw new InvalidOperationException("No se pudo crear el administrador. El usuario o correo ya existe.");
    Console.WriteLine("Administrador creado. No se han impreso credenciales.");
    return;
}

app.UseMiddleware<SecurityHeadersMiddleware>();
app.UseRouting();
app.UseMiddleware<AuditMiddleware>();
app.UseExceptionHandler(handler => handler.Run(async context =>
{
    var error = context.Features.Get<IExceptionHandlerFeature>()?.Error;
    if (error is BadHttpRequestException badRequest)
    {
        await Results.Problem(statusCode: badRequest.StatusCode, title: "La solicitud no es válida o excede el tamaño permitido.").ExecuteAsync(context);
        return;
    }
    app.Logger.LogError(error, "Error interno. RequestId={Id}", context.TraceIdentifier);
    await Results.Problem(statusCode: 500, title: "Error interno del servidor.").ExecuteAsync(context);
}));
if (!app.Environment.IsDevelopment() && !app.Environment.IsEnvironment("Testing"))
{
    app.UseHsts();
    app.UseHttpsRedirection();
}
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();
app.MapGet("/", () => Results.Ok(new { name = "SafeVault", documentation = "README.md", health = "/health" })).AllowAnonymous();
app.MapGet("/health", () => Results.Ok(new { status = "ok" })).AllowAnonymous();
app.MapControllers();
app.Run();
