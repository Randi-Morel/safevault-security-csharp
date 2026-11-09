# SafeVault — seguridad de aplicaciones en C#

API académica con ASP.NET Core 10 y SQLite. Implementa validación de entradas, prevención de inyección SQL, autenticación, autorización por roles (RBAC), aislamiento de notas por propietario, prevención de XSS al generar HTML y pruebas de regresión de seguridad.

## Ejecutar

Requisito: SDK .NET 10. Puedes abrir `SafeVault.slnx` con una versión de Visual Studio compatible con .NET 10 o utilizar la terminal desde la raíz del repositorio.

```sh
dotnet restore SafeVault.slnx --locked-mode
dotnet build SafeVault.slnx -c Release --no-restore
dotnet dev-certs https --trust
dotnet run --project src/SafeVault
```

Usa `https://localhost:7085/health` para verificar el inicio. El perfil de desarrollo también escucha en `http://localhost:5085` para pruebas locales. En producción se aplican HTTPS redirection y HSTS; configura un certificado válido. No se incluye Swagger ni una interfaz gráfica completa: `SafeVault.http` contiene ejemplos para un cliente HTTP de Visual Studio, VS Code o Postman.

SQLite se crea automáticamente en `src/SafeVault/App_Data/safevault.db` al ejecutar con el perfil del proyecto. El archivo conserva cuentas, sesiones y notas tras reiniciar. La ruta se puede cambiar con `Database__Path`; los archivos de datos y las credenciales locales están excluidos de Git.

## Flujo de uso

1. Registra una cuenta mediante `POST /api/auth/register`.
2. Inicia sesión con `POST /api/auth/login` y copia `accessToken` de la respuesta.
3. Envía `Authorization: Bearer TU_TOKEN` en las operaciones privadas.
4. Crea, consulta, actualiza o elimina tus propias notas.
5. Cierra sesión con `POST /api/auth/logout`: el token queda revocado inmediatamente.

Registro de ejemplo, únicamente con datos ficticios:

```json
{
  "username": "usuario_demo",
  "email": "demo@example.test",
  "password": "Frase de ejemplo para pruebas 927!"
}
```

El servidor asigna el rol `User`. Incluir `role`, `id`, `ownerId` u otro campo ajeno al DTO produce 400. Los permisos y la identidad nunca se toman del cuerpo enviado por el cliente.

## Endpoints y permisos

| Método | Ruta | Acceso |
| --- | --- | --- |
| GET | `/health` | Público |
| POST | `/api/auth/register` | Público, limitado por IP |
| POST | `/api/auth/login` | Público, limitado por IP |
| GET | `/api/auth/me` | Sesión válida |
| POST | `/api/auth/logout` | Sesión válida |
| GET | `/api/notes?search=texto` | Solo notas propias |
| GET | `/api/notes/{id}` | Solo propietario |
| POST | `/api/notes` | User o Admin; propietario asignado por servidor |
| PUT | `/api/notes/{id}` | Solo propietario |
| DELETE | `/api/notes/{id}` | Solo propietario |
| GET | `/api/notes/{id}/preview` | Solo propietario; HTML codificado |
| GET | `/api/admin/users` | Exclusivamente Admin; no devuelve hashes |

Notas: `{"title":"Mi nota","content":"Contenido privado"}`. Los IDs son numéricos. Una nota inexistente o perteneciente a otra cuenta devuelve 404. No se permite al administrador leer notas ajenas: su permiso adicional es consultar cuentas. Las respuestas comunes son 201 (creación), 204 (actualización/eliminación), 400 (validación), 401 (sin sesión válida), 403 (rol insuficiente), 409 (cuenta duplicada), 413 (cuerpo excesivo) y 429 (exceso de intentos).

## Crear un administrador local

No existe una contraseña administrativa por defecto ni un endpoint público que eleve privilegios. El administrador se aprovisiona desde la máquina que ejecuta la aplicación. En PowerShell:

```powershell
$env:SAFEVAULT_ADMIN_USERNAME = "admin_local"
$env:SAFEVAULT_ADMIN_EMAIL = "admin@example.test"
$secret = Read-Host "Contraseña administrativa (15 a 128 caracteres)" -AsSecureString
$env:SAFEVAULT_ADMIN_PASSWORD = [System.Net.NetworkCredential]::new("", $secret).Password
try {
    dotnet run --project src/SafeVault -- --create-admin
} finally {
    Remove-Item Env:\SAFEVAULT_ADMIN_PASSWORD
    Remove-Variable secret
}
```

Después inicia la API normalmente e inicia sesión con ese usuario. No publiques credenciales, archivos de base de datos ni tokens reales. Las cuentas repetidas se rechazan; el comando no cambia el rol de una cuenta existente.

## Controles implementados

- DTOs y DataAnnotations: nombre de usuario de 3–32 caracteres alfanuméricos o `_`, correo válido de hasta 254 caracteres, contraseña de 15–128 caracteres, título de hasta 100 y contenido de hasta 4000. Campos obligatorios y búsquedas de hasta 200 caracteres.
- Consultas SQL fijas con parámetros nombrados de `Microsoft.Data.Sqlite`; no se concatena entrada externa, incluidos los campos de búsqueda.
- Hash de contraseñas mediante `PasswordHasher` de ASP.NET Core Identity, PBKDF2-HMAC-SHA512 con 220 000 iteraciones y sal aleatoria. No se cifran ni almacenan contraseñas en claro.
- Tokens opacos aleatorios de 256 bits, SHA-256 del token en la base de datos, vencimiento de 30 minutos y revocación al cerrar sesión. SHA-256 se usa para tokens aleatorios de alta entropía, no para contraseñas.
- El handler de autenticación carga el usuario y su rol actuales de la base de datos. La política de respaldo requiere autenticación salvo excepciones públicas explícitas.
- Cinco fallos de contraseña bloquean esa cuenta durante 15 minutos. Mensaje de error genérico; hash de coste equivalente para usuarios inexistentes. Esto no se presenta como garantía de tiempos idénticos en todos los casos.
- Registro e inicio de sesión comparten un límite de 20 solicitudes por IP y minuto; sin cola. Las pruebas usan límites controlados por su entorno aislado.
- Cada consulta de notas comprueba `OwnerId` a partir de la identidad autenticada, también en PUT, DELETE y preview.
- `HtmlEncoder` para cada dato externo insertado en texto HTML. El contenido de una nota puede conservar `<script>` como dato: se codifica al mostrarlo, no se confunde validación con eliminación de caracteres.
- CSP restrictiva, `nosniff`, `DENY`, `no-referrer`, `no-store` y cabecera de correlación. Se aplican con `OnStarting` para conservarlas en respuestas de error.
- Límite de cuerpo de 16 KiB; errores genéricos sin stack traces en respuestas. Auditoría de método, patrón de ruta, estado y correlación, sin cuerpos ni cabecera Authorization.

## Pruebas de seguridad

```sh
dotnet build SafeVault.slnx -c Release
dotnet run --project tests/SafeVault.SecurityTests -c Release --no-build -- .
```

El proyecto de pruebas es un ejecutable de integración; se ejecuta con `dotnet run`, no con `dotnet test`. Arranca procesos reales de la API, usa HTTP y SQLite real en una carpeta temporal, crea cuentas ficticias, verifica las respuestas y borra sus datos al terminar. Cualquier fallo devuelve código de salida 1. El workflow de GitHub Actions ejecuta los mismos controles con el archivo de dependencias bloqueado.

Incluye reproducciones de SQL vulnerable y HTML sin codificar **solo en fixtures aislados de pruebas**, seguidas de comprobaciones de la versión corregida y de los endpoints reales. No se expone ningún endpoint deliberadamente vulnerable. Ver el análisis de hallazgos en [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md) y los resultados observados en [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md).

## Alcance

Proyecto de demostración para una única instancia; no representa una certificación ni una auditoría exhaustiva. No incluye MFA, recuperación de contraseña, detección de contraseñas comprometidas, cifrado de notas en reposo ni rotación de credenciales. Los bloqueos de cuenta pueden ser abusados para provocar denegación temporal a una víctima; el límite por IP es una mitigación parcial. Antes de desplegar, configura TLS, permisos del archivo SQLite, copias de seguridad, cuotas, limpieza de sesiones expiradas y controles distribuidos. No se configura CORS permisivo ni autenticación automática por cookies; un cliente debe enviar explícitamente el bearer token y protegerlo. Si se añade autenticación por cookies, se necesita protección antiforgery.

## Fuentes técnicas

- [Microsoft: parámetros de SQLite y prevención de SQL injection](https://learn.microsoft.com/en-us/dotnet/standard/data/sqlite/parameters).
- [Microsoft: prevención de XSS en ASP.NET Core](https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0).
- [OWASP: almacenamiento de contraseñas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html).
- [OWASP: seguridad de .NET](https://cheatsheetseries.owasp.org/cheatsheets/DotNet_Security_Cheat_Sheet.html).

La implementación y sus pruebas se prepararon con ChatGPT/Codex. No se atribuye una sesión de depuración a GitHub Copilot sin haberla realizado y verificado.
