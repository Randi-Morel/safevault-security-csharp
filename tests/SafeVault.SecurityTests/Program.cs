using System.Diagnostics;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Sockets;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using SafeVault.Data;
using SafeVault.Security;

// Ejecutable de integración: HTTP real, SQLite real, datos sintéticos y cero mocks de autorización.
var root = Path.GetFullPath(args.Length > 0 ? args[0] : ".");
var dll = Path.Combine(root, "src/SafeVault/bin/Release/net10.0/SafeVault.dll");
if (!File.Exists(dll)) throw new FileNotFoundException("Compila primero en Release.", dll);
var host = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH") ?? "dotnet";
var temporary = Path.Combine(Path.GetTempPath(), "safevault-tests-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(temporary);
var dbPath = Path.Combine(temporary, "test.db");
var logs = new StringBuilder();
var password = "Synthetic test passphrase 927!";
Process? server = null;
using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
var scenarios = 0;
var assertions = 0;
string aliceToken = "", bobToken = "", adminToken = "";
long aliceId = 0, bobId = 0, noteId = 0;
const string sqlPayload = "' OR 1=1 --";
const string xssPayload = "<script>alert('xss')</script><img src=x onerror=alert(1)>";

try
{
    await Scenario("Reproducir bypass SQL en fixture aislado y verificar consulta parametrizada", () =>
    {
        // Fragmento vulnerable SOLO en esta base efímera de prueba. Nunca se usa en la aplicación.
        using var db = new SqliteConnection("Data Source=:memory:");
        db.Open();
        using var command = db.CreateCommand();
        command.CommandText = "CREATE TABLE Fixture (Username TEXT); INSERT INTO Fixture VALUES ('alice');";
        command.ExecuteNonQuery();
        command.CommandText = "SELECT COUNT(*) FROM Fixture WHERE Username='" + sqlPayload + "'";
        Require((long)command.ExecuteScalar()! == 1, "El patrón vulnerable debe reproducir el bypass");
        command.CommandText = "SELECT COUNT(*) FROM Fixture WHERE Username=$username";
        command.Parameters.AddWithValue("$username", sqlPayload);
        Require((long)command.ExecuteScalar()! == 0, "El parámetro debe tratar el ataque como dato literal");
        return Task.CompletedTask;
    });

    await Scenario("Reproducir HTML sin codificar y comprobar codificación de salida", () =>
    {
        var unsafeExample = "<pre>" + xssPayload + "</pre>";
        var safeExample = "<pre>" + HtmlEncoder.Default.Encode(xssPayload) + "</pre>";
        Require(unsafeExample.Contains("<script>"), "Fixture contiene etiqueta peligrosa");
        Require(!safeExample.Contains("<script>") && safeExample.Contains("&lt;script&gt;"), "La salida corregida muestra texto");
        return Task.CompletedTask;
    });

    await Bootstrap();
    await StartServer(100);

    await Scenario("Endpoints privados requieren autenticación", async () =>
    {
        await Check(HttpMethod.Get, "/api/notes", 401);
        await Check(HttpMethod.Get, "/api/admin/users", 401);
        await Check(HttpMethod.Get, "/api/auth/me", 401);
    });

    await Scenario("Registro válido y rol User asignado por servidor", async () =>
    {
        var alice = await Check(HttpMethod.Post, "/api/auth/register", 201, new { username = "alice_test", email = "alice@example.test", password });
        aliceId = alice.GetProperty("id").GetInt64();
        Require(alice.GetProperty("role").GetString() == "User", "El registro no concede Admin");
        var bob = await Check(HttpMethod.Post, "/api/auth/register", 201, new { username = "bob_test", email = "bob@example.test", password });
        bobId = bob.GetProperty("id").GetInt64();
    });

    await Scenario("Rechazar nombre inválido, correo inválido y contraseñas cortas o enormes", async () =>
    {
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = "<script>", email = "ok@example.test", password });
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = "valid_user", email = "bad", password });
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = "valid_user", email = "ok@example.test", password = "short" });
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = "valid_user", email = "ok@example.test", password = new string('x', 129) });
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = " ", email = "ok@example.test", password });
    });

    await Scenario("Rechazar escalada de privilegios y campos desconocidos", async () =>
    {
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = "attacker", email = "attacker@example.test", password, role = "Admin" });
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = "attacker", email = "attacker@example.test", password, id = 1 });
    });

    await Scenario("Rechazar cuentas duplicadas sin distinguir mayúsculas", async () =>
    {
        await Check(HttpMethod.Post, "/api/auth/register", 409, new { username = "ALICE_TEST", email = "other@example.test", password });
        await Check(HttpMethod.Post, "/api/auth/register", 409, new { username = "other_test", email = "ALICE@example.test", password });
    });

    await Scenario("Inyección SQL no permite iniciar sesión", async () =>
    {
        await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = sqlPayload, password });
        await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = "alice_test", password = "' OR '1'='1" });
        await Check(HttpMethod.Post, "/api/auth/register", 400, new { username = sqlPayload, email = "sql@example.test", password });
    });

    await Scenario("Contraseña incorrecta y usuario inexistente reciben mismo error", async () =>
    {
        var a = await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = "alice_test", password = "incorrect-password" });
        var b = await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = "missing_user", password = "incorrect-password" });
        Require(a.GetProperty("title").GetString() == b.GetProperty("title").GetString(), "No revelar existencia en el mensaje");
    });

    await Scenario("Iniciar sesión como dos usuarios y administrador", async () =>
    {
        aliceToken = await Login("alice_test");
        bobToken = await Login("bob_test");
        adminToken = await Login("vault_admin");
        var me = await Check(HttpMethod.Get, "/api/auth/me", 200, token: aliceToken);
        Require(me.GetProperty("id").GetInt64() == aliceId, "Identidad autenticada correcta");
    });

    await Scenario("Roles: User recibe 403 y Admin puede consultar cuentas", async () =>
    {
        await Check(HttpMethod.Get, "/api/admin/users", 403, token: aliceToken);
        var accounts = await Check(HttpMethod.Get, "/api/admin/users", 200, token: adminToken);
        Require(accounts.GetArrayLength() == 3, "Se devuelven las tres cuentas válidas");
        Require(!accounts.ToString().Contains("password", StringComparison.OrdinalIgnoreCase), "No devolver hashes ni contraseñas");
    });

    await Scenario("Tokens falsos, manipulados y esquemas incorrectos reciben 401", async () =>
    {
        await Check(HttpMethod.Get, "/api/auth/me", 401, token: new string('A', 64));
        var modified = (aliceToken[0] == 'A' ? "B" : "A") + aliceToken[1..];
        await Check(HttpMethod.Get, "/api/auth/me", 401, token: modified);
        using var message = new HttpRequestMessage(HttpMethod.Get, "/api/auth/me");
        message.Headers.Authorization = new AuthenticationHeaderValue("Basic", "invalid");
        using var response = await client.SendAsync(message);
        Require(response.StatusCode == HttpStatusCode.Unauthorized, "Rechazar esquema Basic");
    });

    await Scenario("CRUD válido con Location y pertenencia al usuario autenticado", async () =>
    {
        var note = await Check(HttpMethod.Post, "/api/notes", 201, new { title = "Nota privada", content = "Contenido de Alice" }, aliceToken);
        noteId = note.GetProperty("id").GetInt64();
        Require(note.GetProperty("ownerId").GetInt64() == aliceId, "Owner procede de la identidad");
        await Check(HttpMethod.Get, $"/api/notes/{noteId}", 200, token: aliceToken);
        await Check(HttpMethod.Put, $"/api/notes/{noteId}", 204, new { title = "Actualizada", content = "Actualización persistida" }, aliceToken);
    });

    await Scenario("Bloquear lectura, edición, eliminación y preview de notas ajenas", async () =>
    {
        await Check(HttpMethod.Get, $"/api/notes/{noteId}", 404, token: bobToken);
        await Check(HttpMethod.Put, $"/api/notes/{noteId}", 404, new { title = "Ataque", content = "No permitido" }, bobToken);
        await Check(HttpMethod.Delete, $"/api/notes/{noteId}", 404, token: bobToken);
        await Check(HttpMethod.Get, $"/api/notes/{noteId}/preview", 404, token: bobToken);
        var list = await Check(HttpMethod.Get, "/api/notes", 200, token: bobToken);
        Require(list.GetArrayLength() == 0, "Lista limitada al propietario");
    });

    await Scenario("Bloquear modificación masiva de OwnerId", async () =>
    {
        await Check(HttpMethod.Post, "/api/notes", 400, new { title = "Ataque", content = "No permitido", ownerId = aliceId }, bobToken);
    });

    await Scenario("Validación de notas y búsqueda demasiado larga", async () =>
    {
        await Check(HttpMethod.Post, "/api/notes", 400, new { title = " ", content = "Contenido" }, aliceToken);
        await Check(HttpMethod.Post, "/api/notes", 400, new { title = new string('x', 101), content = "Contenido" }, aliceToken);
        await Check(HttpMethod.Post, "/api/notes", 400, new { title = "Título", content = new string('x', 4001) }, aliceToken);
        await Check(HttpMethod.Get, "/api/notes?search=" + new string('x', 201), 400, token: aliceToken);
    });

    await Scenario("Guardar SQL como texto no ejecuta DROP TABLE ni altera cuentas", async () =>
    {
        const string storedSql = "'; DROP TABLE Users; --";
        var note = await Check(HttpMethod.Post, "/api/notes", 201, new { title = "SQL literal", content = storedSql }, aliceToken);
        Require(note.GetProperty("content").GetString() == storedSql, "Conservar dato literal");
        var accounts = await Check(HttpMethod.Get, "/api/admin/users", 200, token: adminToken);
        Require(accounts.GetArrayLength() == 3, "La tabla Users continúa intacta");
        var search = await Check(HttpMethod.Get, "/api/notes?search=" + Uri.EscapeDataString(sqlPayload), 200, token: bobToken);
        Require(search.GetArrayLength() == 0, "La búsqueda no ignora el filtro de propietario");
    });

    await Scenario("XSS almacenado se codifica en título y contenido HTML", async () =>
    {
        var note = await Check(HttpMethod.Post, "/api/notes", 201, new { title = "<svg onload=alert(1)>", content = xssPayload }, aliceToken);
        var id = note.GetProperty("id").GetInt64();
        using var message = new HttpRequestMessage(HttpMethod.Get, $"/api/notes/{id}/preview");
        message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", aliceToken);
        using var response = await client.SendAsync(message);
        var html = await response.Content.ReadAsStringAsync();
        Require(response.IsSuccessStatusCode, "Vista previa disponible");
        Require(response.Content.Headers.ContentType?.MediaType == "text/html", "Contexto HTML real");
        Require(!html.Contains("<script>") && !html.Contains("<img") && !html.Contains("<svg"), "Ninguna etiqueta atacante se emite sin codificar");
        Require(html.Contains("&lt;script&gt;") && html.Contains("&lt;svg"), "Texto codificado presente");
        Require(response.Headers.GetValues("Content-Security-Policy").Single().Contains("default-src 'none'"), "CSP restrictiva");
    });

    await Scenario("JSON inválido, null y cuerpo excesivo son rechazados", async () =>
    {
        foreach (var body in new[] { "{bad", "null" })
        {
            using var message = new HttpRequestMessage(HttpMethod.Post, "/api/notes") { Content = new StringContent(body, Encoding.UTF8, "application/json") };
            message.Headers.Authorization = new AuthenticationHeaderValue("Bearer", aliceToken);
            using var response = await client.SendAsync(message);
            Require(response.StatusCode == HttpStatusCode.BadRequest, "Rechazar JSON inválido");
        }
        await Check(HttpMethod.Post, "/api/notes", 413, new { title = "Grande", content = new string('x', 20_000) }, aliceToken);
    });

    await Scenario("Hashes con sal, PBKDF2 y tokens no almacenados en claro", async () =>
    {
        using var db = Database();
        using var command = db.CreateCommand();
        command.CommandText = "SELECT PasswordHash FROM Users WHERE Id IN ($alice,$bob) ORDER BY Id";
        command.Parameters.AddWithValue("$alice", aliceId);
        command.Parameters.AddWithValue("$bob", bobId);
        using var reader = command.ExecuteReader();
        Require(reader.Read(), "Hash de Alice presente");
        var first = reader.GetString(0);
        Require(reader.Read(), "Hash de Bob presente");
        var second = reader.GetString(0);
        Require(first != password && first != second, "Misma contraseña, hashes distintos por sal");
        Require(new PasswordService().Verify(first, password), "Hash verificable por Identity");
        reader.Close();
        command.CommandText = "SELECT TokenHash FROM Sessions";
        command.Parameters.Clear();
        using var tokens = command.ExecuteReader();
        while (tokens.Read()) Require(tokens.GetString(0) != aliceToken && tokens.GetString(0) != bobToken && tokens.GetString(0) != adminToken, "Token no guardado en claro");
    });

    await Scenario("Sesión expirada rechazada por el servidor", async () =>
    {
        var expired = await Login("bob_test");
        using var db = Database();
        using var command = db.CreateCommand();
        command.CommandText = "UPDATE Sessions SET ExpiresAt=$expires WHERE TokenHash=$hash";
        command.Parameters.AddWithValue("$expires", DateTimeOffset.UtcNow.AddSeconds(-1).ToUnixTimeSeconds());
        command.Parameters.AddWithValue("$hash", VaultStore.TokenHash(expired));
        command.ExecuteNonQuery();
        await Check(HttpMethod.Get, "/api/auth/me", 401, token: expired);
    });

    await Scenario("Logout revoca el token inmediatamente", async () =>
    {
        var revoked = await Login("bob_test");
        await Check(HttpMethod.Post, "/api/auth/logout", 204, token: revoked);
        await Check(HttpMethod.Get, "/api/auth/me", 401, token: revoked);
    });

    await Scenario("Bloqueo tras cinco fallos impide usar incluso la contraseña correcta", async () =>
    {
        for (var i = 0; i < 5; i++) await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = "bob_test", password = "invalid-password" });
        await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = "bob_test", password });
    });

    await Scenario("Datos y sesiones sobreviven al reinicio", async () =>
    {
        StopServer();
        await StartServer(100);
        var note = await Check(HttpMethod.Get, $"/api/notes/{noteId}", 200, token: aliceToken);
        Require(note.GetProperty("title").GetString() == "Actualizada", "Actualización persistida");
    });

    await Scenario("Eliminar nota y obtener 404 después", async () =>
    {
        await Check(HttpMethod.Delete, $"/api/notes/{noteId}", 204, token: aliceToken);
        await Check(HttpMethod.Get, $"/api/notes/{noteId}", 404, token: aliceToken);
    });

    await Scenario("Rate limiting rechaza exceso de intentos con 429", async () =>
    {
        StopServer();
        await StartServer(3);
        for (var i = 0; i < 3; i++) await Check(HttpMethod.Post, "/api/auth/login", 401, new { username = "missing_user", password });
        await Check(HttpMethod.Post, "/api/auth/login", 429, new { username = "missing_user", password });
    });

    StopServer();
    await Scenario("Auditoría no contiene contraseñas, tokens ni payloads", () =>
    {
        var text = logs.ToString();
        Require(text.Contains("RequestId="), "Auditoría presente");
        Require(!text.Contains(password) && !text.Contains(aliceToken) && !text.Contains(sqlPayload) && !text.Contains(xssPayload), "No registrar material sensible ni entradas controladas");
        return Task.CompletedTask;
    });

    Console.WriteLine($"RESULTADO: {scenarios} escenarios y {assertions} aserciones superados.");
}
catch (Exception ex)
{
    Console.Error.WriteLine("FALLO: " + ex.Message);
    Console.Error.WriteLine(logs.ToString());
    Environment.ExitCode = 1;
}
finally
{
    StopServer();
    SqliteConnection.ClearAllPools();
    Directory.Delete(temporary, recursive: true);
}

async Task Scenario(string name, Func<Task> action)
{
    await action();
    scenarios++;
    Console.WriteLine("PASS " + name);
}

void Require(bool condition, string message)
{
    assertions++;
    if (!condition) throw new Exception(message);
}

async Task<JsonElement> Check(HttpMethod method, string path, int expected, object? body = null, string? token = null)
{
    using var request = new HttpRequestMessage(method, path);
    if (body is not null) request.Content = JsonContent.Create(body);
    if (token is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
    using var response = await client.SendAsync(request);
    var text = await response.Content.ReadAsStringAsync();
    Require((int)response.StatusCode == expected, $"{method} {path}: esperado {expected}, recibido {(int)response.StatusCode}: {text}");
    Require(response.Headers.Contains("X-Content-Type-Options"), "Cabecera nosniff");
    Require(response.Headers.CacheControl?.NoStore == true, "Respuesta no almacenable");
    if (method == HttpMethod.Post && path == "/api/notes" && expected == 201)
        Require(response.Headers.Location is not null, "POST devuelve Location");
    return text.Length == 0 ? default : JsonSerializer.Deserialize<JsonElement>(text);
}

async Task<string> Login(string username)
{
    var result = await Check(HttpMethod.Post, "/api/auth/login", 200, new { username, password });
    var token = result.GetProperty("accessToken").GetString()!;
    Require(token.Length == 64 && token.All(char.IsAsciiHexDigit), "Token aleatorio de 256 bits");
    Require(result.GetProperty("expiresAt").GetDateTimeOffset() > DateTimeOffset.UtcNow, "Fecha de vencimiento futura");
    return token;
}

SqliteConnection Database()
{
    var db = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = dbPath }.ToString());
    db.Open();
    return db;
}

ProcessStartInfo ProcessInfo()
{
    var info = new ProcessStartInfo(host) { WorkingDirectory = temporary, RedirectStandardOutput = true, RedirectStandardError = true };
    info.ArgumentList.Add(dll);
    info.Environment["ASPNETCORE_ENVIRONMENT"] = "Testing";
    info.Environment["Database__Path"] = dbPath;
    info.Environment["Logging__LogLevel__Microsoft.AspNetCore"] = "Warning";
    return info;
}

async Task Bootstrap()
{
    var info = ProcessInfo();
    info.ArgumentList.Add("--create-admin");
    info.Environment["SAFEVAULT_ADMIN_USERNAME"] = "vault_admin";
    info.Environment["SAFEVAULT_ADMIN_EMAIL"] = "admin@example.test";
    info.Environment["SAFEVAULT_ADMIN_PASSWORD"] = password;
    using var process = Process.Start(info)!;
    var stdout = process.StandardOutput.ReadToEndAsync();
    var stderr = process.StandardError.ReadToEndAsync();
    await process.WaitForExitAsync();
    var result = await stdout + await stderr;
    Require(process.ExitCode == 0, "Aprovisionamiento Admin: " + result);
}

async Task StartServer(int permitLimit)
{
    var listener = new TcpListener(IPAddress.Loopback, 0);
    listener.Start();
    var port = ((IPEndPoint)listener.LocalEndpoint).Port;
    listener.Stop();
    if (client.BaseAddress is null) client.BaseAddress = new Uri($"http://127.0.0.1:{port}");
    // HttpClient no permite cambiar BaseAddress tras la primera solicitud: reutilizar el puerto.
    var info = ProcessInfo();
    info.Environment["ASPNETCORE_URLS"] = client.BaseAddress.ToString().TrimEnd('/');
    info.Environment["RateLimits__AuthPermitLimit"] = permitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture);
    server = Process.Start(info)!;
    server.OutputDataReceived += (_, e) => { lock (logs) logs.AppendLine(e.Data); };
    server.ErrorDataReceived += (_, e) => { lock (logs) logs.AppendLine(e.Data); };
    server.BeginOutputReadLine();
    server.BeginErrorReadLine();
    for (var attempt = 0; attempt < 100; attempt++)
    {
        if (server.HasExited) throw new Exception("El servidor terminó antes de iniciar.");
        try
        {
            using var response = await client.GetAsync("/health");
            if (response.IsSuccessStatusCode) return;
        }
        catch (HttpRequestException) { }
        await Task.Delay(100);
    }
    throw new TimeoutException("La API no inició.");
}

void StopServer()
{
    if (server is null) return;
    if (!server.HasExited) server.Kill(entireProcessTree: true);
    server.WaitForExit();
    server.Dispose();
    server = null;
}
