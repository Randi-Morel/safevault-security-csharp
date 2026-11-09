using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Security;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public sealed class AuthController(VaultStore store, PasswordService passwords, TimeProvider clock) : ControllerBase
{
    [AllowAnonymous, HttpPost("register"), EnableRateLimiting("auth")]
    public IActionResult Register(RegisterRequest request)
    {
        var user = store.CreateAccount(request.Username, request.Email.ToLowerInvariant(), passwords.Hash(request.Password));
        return user is null
            ? Problem(statusCode: 409, title: "No se puede registrar esa cuenta.")
            : StatusCode(201, new PublicAccount(user.Id, user.Username, user.Email, user.Role));
    }

    [AllowAnonymous, HttpPost("login"), EnableRateLimiting("auth")]
    public IActionResult Login(LoginRequest request)
    {
        var user = store.FindAccount(request.Username);
        if (user is null)
        {
            passwords.DummyVerify(request.Password);
            return InvalidLogin();
        }
        if (!store.VerifyLogin(user, clock.GetUtcNow().ToUnixTimeSeconds(), () => passwords.Verify(user.PasswordHash, request.Password)))
            return InvalidLogin();
        var token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        var expires = clock.GetUtcNow().AddMinutes(30);
        store.AddSession(user.Id, token, expires.ToUnixTimeSeconds());
        return Ok(new SessionResult(token, expires));
    }

    [Authorize, HttpGet("me")]
    public IActionResult Me() => Ok(new
    {
        id = long.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!, System.Globalization.CultureInfo.InvariantCulture),
        username = User.Identity!.Name,
        role = User.FindFirstValue(ClaimTypes.Role)
    });

    [Authorize, HttpPost("logout")]
    public IActionResult Logout()
    {
        store.RevokeSession(Request.Headers.Authorization.ToString()[7..]);
        return NoContent();
    }

    private ObjectResult InvalidLogin() => Problem(statusCode: 401, title: "Credenciales inválidas o cuenta temporalmente bloqueada.");
}
