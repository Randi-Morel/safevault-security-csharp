using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;

namespace SafeVault.Controllers;

[ApiController, Authorize(Roles = "Admin")]
[Route("api/admin")]
public sealed class AdminController(VaultStore store) : ControllerBase
{
    [HttpGet("users")]
    public IActionResult UsersList() => Ok(store.Accounts());
}
