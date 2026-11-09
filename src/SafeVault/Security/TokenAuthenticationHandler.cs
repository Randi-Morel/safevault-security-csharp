using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using SafeVault.Data;

namespace SafeVault.Security;

public sealed class TokenAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder, VaultStore store, TimeProvider clock)
    : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    public const string SchemeName = "VaultBearer";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var header = Request.Headers.Authorization.ToString();
        if (string.IsNullOrEmpty(header)) return Task.FromResult(AuthenticateResult.NoResult());
        if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            return Task.FromResult(AuthenticateResult.Fail("Formato de autorización inválido."));

        var token = header[7..];
        if (token.Length != 64 || !token.All(char.IsAsciiHexDigit))
            return Task.FromResult(AuthenticateResult.Fail("Token inválido."));

        var account = store.ResolveSession(token, clock.GetUtcNow().ToUnixTimeSeconds());
        if (account is null) return Task.FromResult(AuthenticateResult.Fail("Sesión inválida o expirada."));
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, account.Id.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new Claim(ClaimTypes.Name, account.Username),
            new Claim(ClaimTypes.Role, account.Role)
        };
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, SchemeName));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, SchemeName)));
    }

    protected override Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        Response.Headers.WWWAuthenticate = "Bearer";
        return base.HandleChallengeAsync(properties);
    }
}
