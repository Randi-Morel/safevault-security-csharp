using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

// Instancia única, conexiones breves y transacciones para cambios de autenticación.
// Los valores externos SIEMPRE se enlazan como parámetros, nunca se concatenan en SQL.
public sealed class VaultStore
{
    private readonly string _connectionString;
    private readonly object _gate = new();

    public VaultStore(IConfiguration configuration, IWebHostEnvironment environment)
    {
        var path = Path.GetFullPath(configuration["Database:Path"] ?? "App_Data/safevault.db", environment.ContentRootPath);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        _connectionString = new SqliteConnectionStringBuilder { DataSource = path, ForeignKeys = true }.ToString();
        using var db = Open();
        using var cmd = Command(db, """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS Users (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL COLLATE NOCASE UNIQUE,
                Email TEXT NOT NULL COLLATE NOCASE UNIQUE,
                Role TEXT NOT NULL CHECK (Role IN ('User','Admin')),
                PasswordHash TEXT NOT NULL,
                FailedAttempts INTEGER NOT NULL DEFAULT 0,
                LockedUntil INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS Sessions (
                TokenHash TEXT PRIMARY KEY,
                UserId INTEGER NOT NULL REFERENCES Users(Id) ON DELETE CASCADE,
                ExpiresAt INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS Notes (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                OwnerId INTEGER NOT NULL REFERENCES Users(Id) ON DELETE CASCADE,
                Title TEXT NOT NULL,
                Content TEXT NOT NULL
            );
            """);
        cmd.ExecuteNonQuery();
    }

    public Account? FindAccount(string username)
    {
        using var db = Open();
        using var cmd = Command(db, "SELECT Id,Username,Email,Role,PasswordHash FROM Users WHERE Username=$username", ("$username", username));
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? ReadAccount(reader) : null;
    }

    public Account? CreateAccount(string username, string email, string passwordHash, string role = "User")
    {
        lock (_gate)
        {
            using var db = Open();
            using var cmd = Command(db, """
                INSERT INTO Users (Username,Email,Role,PasswordHash) VALUES ($username,$email,$role,$hash)
                RETURNING Id,Username,Email,Role,PasswordHash;
                """, ("$username", username), ("$email", email), ("$role", role), ("$hash", passwordHash));
            try
            {
                using var reader = cmd.ExecuteReader();
                return reader.Read() ? ReadAccount(reader) : null;
            }
            catch (SqliteException ex) when (ex.SqliteErrorCode == 19) { return null; }
        }
    }

    // Verificación y actualización bajo un mismo bloqueo y transacción: sin carrera de bloqueo.
    public bool VerifyLogin(Account account, long now, Func<bool> verifyPassword)
    {
        lock (_gate)
        {
            using var db = Open();
            using var transaction = db.BeginTransaction();
            using var read = Command(db, "SELECT FailedAttempts,LockedUntil FROM Users WHERE Id=$id", ("$id", account.Id));
            read.Transaction = transaction;
            int failed;
            long locked;
            using (var reader = read.ExecuteReader())
            {
                if (!reader.Read()) return false;
                failed = reader.GetInt32(0);
                locked = reader.GetInt64(1);
            }
            if (locked > now) return false;
            if (locked != 0) failed = 0;
            var valid = verifyPassword();
            var nextFailed = valid ? 0 : failed + 1;
            using var update = Command(db, "UPDATE Users SET FailedAttempts=$failed,LockedUntil=$until WHERE Id=$id",
                ("$failed", nextFailed), ("$until", !valid && nextFailed >= 5 ? now + 900 : 0L), ("$id", account.Id));
            update.Transaction = transaction;
            update.ExecuteNonQuery();
            transaction.Commit();
            return valid;
        }
    }

    public void AddSession(long userId, string token, long expiresAt)
    {
        using var db = Open();
        using var cmd = Command(db, "INSERT INTO Sessions (TokenHash,UserId,ExpiresAt) VALUES ($hash,$user,$expires)",
            ("$hash", TokenHash(token)), ("$user", userId), ("$expires", expiresAt));
        cmd.ExecuteNonQuery();
    }

    public Account? ResolveSession(string token, long now)
    {
        using var db = Open();
        using var cmd = Command(db, """
            SELECT u.Id,u.Username,u.Email,u.Role,u.PasswordHash FROM Sessions s JOIN Users u ON u.Id=s.UserId
            WHERE s.TokenHash=$hash AND s.ExpiresAt>$now
            """, ("$hash", TokenHash(token)), ("$now", now));
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? ReadAccount(reader) : null;
    }

    public void RevokeSession(string token)
    {
        using var db = Open();
        using var cmd = Command(db, "DELETE FROM Sessions WHERE TokenHash=$hash", ("$hash", TokenHash(token)));
        cmd.ExecuteNonQuery();
    }

    public PublicAccount[] Accounts()
    {
        using var db = Open();
        using var cmd = Command(db, "SELECT Id,Username,Email,Role FROM Users ORDER BY Id");
        using var reader = cmd.ExecuteReader();
        var result = new List<PublicAccount>();
        while (reader.Read()) result.Add(new(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)));
        return result.ToArray();
    }

    public Note CreateNote(long owner, string title, string content)
    {
        using var db = Open();
        using var cmd = Command(db, "INSERT INTO Notes (OwnerId,Title,Content) VALUES ($owner,$title,$content) RETURNING Id",
            ("$owner", owner), ("$title", title), ("$content", content));
        return new((long)cmd.ExecuteScalar()!, owner, title, content);
    }

    public Note[] Notes(long owner, string search)
    {
        using var db = Open();
        // instr hace búsqueda literal. Ni siquiera '%' o '_' se interpretan como comodines.
        using var cmd = Command(db, """
            SELECT Id,OwnerId,Title,Content FROM Notes
            WHERE OwnerId=$owner AND ($search='' OR instr(Title,$search)>0 OR instr(Content,$search)>0) ORDER BY Id
            """, ("$owner", owner), ("$search", search));
        using var reader = cmd.ExecuteReader();
        var result = new List<Note>();
        while (reader.Read()) result.Add(ReadNote(reader));
        return result.ToArray();
    }

    public Note? FindNote(long id, long owner)
    {
        using var db = Open();
        using var cmd = Command(db, "SELECT Id,OwnerId,Title,Content FROM Notes WHERE Id=$id AND OwnerId=$owner", ("$id", id), ("$owner", owner));
        using var reader = cmd.ExecuteReader();
        return reader.Read() ? ReadNote(reader) : null;
    }

    public bool UpdateNote(long id, long owner, string title, string content)
    {
        using var db = Open();
        using var cmd = Command(db, "UPDATE Notes SET Title=$title,Content=$content WHERE Id=$id AND OwnerId=$owner",
            ("$title", title), ("$content", content), ("$id", id), ("$owner", owner));
        return cmd.ExecuteNonQuery() == 1;
    }

    public bool DeleteNote(long id, long owner)
    {
        using var db = Open();
        using var cmd = Command(db, "DELETE FROM Notes WHERE Id=$id AND OwnerId=$owner", ("$id", id), ("$owner", owner));
        return cmd.ExecuteNonQuery() == 1;
    }

    public static string TokenHash(string token) => Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));

    private SqliteConnection Open()
    {
        var db = new SqliteConnection(_connectionString);
        db.Open();
        return db;
    }

    private static SqliteCommand Command(SqliteConnection db, string sql, params (string Name, object Value)[] parameters)
    {
        var cmd = db.CreateCommand();
        cmd.CommandText = sql;
        foreach (var parameter in parameters) cmd.Parameters.AddWithValue(parameter.Name, parameter.Value);
        return cmd;
    }

    private static Account ReadAccount(SqliteDataReader r) => new(r.GetInt64(0), r.GetString(1), r.GetString(2), r.GetString(3), r.GetString(4));
    private static Note ReadNote(SqliteDataReader r) => new(r.GetInt64(0), r.GetInt64(1), r.GetString(2), r.GetString(3));
}
