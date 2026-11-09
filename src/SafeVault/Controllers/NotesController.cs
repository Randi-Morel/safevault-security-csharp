using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Models;

namespace SafeVault.Controllers;

[ApiController, Authorize(Roles = "User,Admin")]
[Route("api/notes")]
public sealed class NotesController(VaultStore store) : ControllerBase
{
    private long Owner => long.Parse(User.FindFirstValue(ClaimTypes.NameIdentifier)!, System.Globalization.CultureInfo.InvariantCulture);

    [HttpGet]
    public IActionResult List([FromQuery, StringLength(200)] string search = "") => Ok(store.Notes(Owner, search));

    [HttpGet("{id:long}")]
    public IActionResult Get(long id) => store.FindNote(id, Owner) is { } note ? Ok(note) : Missing();

    [HttpPost]
    public IActionResult Create(NoteRequest request)
    {
        var note = store.CreateNote(Owner, request.Title, request.Content);
        return CreatedAtAction(nameof(Get), new { id = note.Id }, note);
    }

    [HttpPut("{id:long}")]
    public IActionResult Update(long id, NoteRequest request) => store.UpdateNote(id, Owner, request.Title, request.Content)
        ? NoContent() : Missing();

    [HttpDelete("{id:long}")]
    public IActionResult Delete(long id) => store.DeleteNote(id, Owner) ? NoContent() : Missing();

    [HttpGet("{id:long}/preview")]
    public IActionResult Preview(long id)
    {
        var note = store.FindNote(id, Owner);
        if (note is null) return Missing();
        // Solo contexto de texto HTML. No insertar estos valores en scripts, URLs o atributos.
        var title = HtmlEncoder.Default.Encode(note.Title);
        var content = HtmlEncoder.Default.Encode(note.Content);
        return Content($"<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>{title}</title></head><body><h1>{title}</h1><pre>{content}</pre></body></html>", "text/html; charset=utf-8");
    }

    private ObjectResult Missing() => Problem(statusCode: 404, title: "Nota no encontrada.");
}
