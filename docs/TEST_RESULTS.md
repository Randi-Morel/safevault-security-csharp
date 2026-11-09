# Resultados observados

Fecha: 9 de noviembre de 2026 (America/Santo_Domingo).

Entorno: Linux, SDK .NET 10.0.403, Release; API y SQLite reales con datos sintéticos temporales.

Compilación: **0 errores y 0 advertencias**.

Pruebas: **27 escenarios y 235 aserciones superados**. El total de aserciones incluye comprobaciones de estado HTTP y cabeceras; no representa 235 ataques independientes.

Comandos ejecutados desde la raíz:

```sh
dotnet build SafeVault.slnx -c Release
dotnet run --project tests/SafeVault.SecurityTests -c Release --no-build -- .
```

Salida observada:

```text
PASS Reproducir bypass SQL en fixture aislado y verificar consulta parametrizada
PASS Reproducir HTML sin codificar y comprobar codificación de salida
PASS Endpoints privados requieren autenticación
PASS Registro válido y rol User asignado por servidor
PASS Rechazar nombre inválido, correo inválido y contraseñas cortas o enormes
PASS Rechazar escalada de privilegios y campos desconocidos
PASS Rechazar cuentas duplicadas sin distinguir mayúsculas
PASS Inyección SQL no permite iniciar sesión
PASS Contraseña incorrecta y usuario inexistente reciben mismo error
PASS Iniciar sesión como dos usuarios y administrador
PASS Roles: User recibe 403 y Admin puede consultar cuentas
PASS Tokens falsos, manipulados y esquemas incorrectos reciben 401
PASS CRUD válido con Location y pertenencia al usuario autenticado
PASS Bloquear lectura, edición, eliminación y preview de notas ajenas
PASS Bloquear modificación masiva de OwnerId
PASS Validación de notas y búsqueda demasiado larga
PASS Guardar SQL como texto no ejecuta DROP TABLE ni altera cuentas
PASS XSS almacenado se codifica en título y contenido HTML
PASS JSON inválido, null y cuerpo excesivo son rechazados
PASS Hashes con sal, PBKDF2 y tokens no almacenados en claro
PASS Sesión expirada rechazada por el servidor
PASS Logout revoca el token inmediatamente
PASS Bloqueo tras cinco fallos impide usar incluso la contraseña correcta
PASS Datos y sesiones sobreviven al reinicio
PASS Eliminar nota y obtener 404 después
PASS Rate limiting rechaza exceso de intentos con 429
PASS Auditoría no contiene contraseñas, tokens ni payloads
RESULTADO: 27 escenarios y 235 aserciones superados.
```

Las pruebas que detectaron inicialmente 500 en vez de 413 y pérdida de cabeceras se volvieron a ejecutar después de aplicar las correcciones. La ejecución final terminó con código 0.

El escenario de expiración modifica el vencimiento en la base temporal para comprobar el rechazo del token; no espera 30 minutos. XSS se verifica mediante el HTML y las cabeceras devueltos, sin ejecutar un navegador. No se ha comprobado en este entorno la interfaz de Visual Studio ni el certificado TLS en Windows.
