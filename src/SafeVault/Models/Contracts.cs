using System.ComponentModel.DataAnnotations;

namespace SafeVault.Models;

public sealed class RegisterRequest
{
    [Required, RegularExpression("^[a-zA-Z0-9_]{3,32}$")]
    public string Username { get; set; } = "";

    [Required, EmailAddress, StringLength(254)]
    public string Email { get; set; } = "";

    [Required, StringLength(128, MinimumLength = 15)]
    public string Password { get; set; } = "";
}

public sealed class LoginRequest
{
    [Required, StringLength(128)]
    public string Username { get; set; } = "";

    [Required, StringLength(128)]
    public string Password { get; set; } = "";
}

public sealed class NoteRequest
{
    [Required, StringLength(100)]
    public string Title { get; set; } = "";

    [Required, StringLength(4000)]
    public string Content { get; set; } = "";
}

public sealed record Account(long Id, string Username, string Email, string Role, string PasswordHash);
public sealed record PublicAccount(long Id, string Username, string Email, string Role);
public sealed record Note(long Id, long OwnerId, string Title, string Content);
public sealed record SessionResult(string AccessToken, DateTimeOffset ExpiresAt);
