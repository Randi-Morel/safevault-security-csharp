using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace SafeVault.Security;

public sealed class PasswordService
{
    private readonly object _user = new();
    private readonly PasswordHasher<object> _hasher = new(Options.Create(new PasswordHasherOptions { IterationCount = 220_000 }));
    private readonly string _dummyHash;

    public PasswordService() => _dummyHash = Hash(Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)));
    public string Hash(string password) => _hasher.HashPassword(_user, password);
    public bool Verify(string hash, string password) => _hasher.VerifyHashedPassword(_user, hash, password) != PasswordVerificationResult.Failed;
    public void DummyVerify(string password) => Verify(_dummyHash, password);
}
