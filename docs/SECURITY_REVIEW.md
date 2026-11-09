# Revisión y correcciones de seguridad

## Método y alcance

Se crearon reproducciones mínimas y aisladas de dos patrones vulnerables (SQL concatenado y salida HTML sin codificar), se implementaron las alternativas seguras y se ejecutaron pruebas de regresión contra la API real. Los ejemplos vulnerables existen únicamente en el ejecutable de pruebas con datos sintéticos. No se afirma que procedan de actividades anteriores no proporcionadas ni que una auditoría externa haya certificado la aplicación.

| Hallazgo o riesgo | Corrección aplicada | Verificación |
| --- | --- | --- |
| SQL concatenado permite interpretar `' OR 1=1 --` como parte de la consulta | SQL fijo y parámetros nombrados en todas las consultas con datos externos | El fixture vulnerable reproduce el bypass; la consulta parametrizada y el login real lo rechazan |
| Insertar contenido de notas directamente en HTML permite XSS almacenado | `HtmlEncoder.Default.Encode` en título y contenido, más CSP restrictiva | Payloads script, img/onerror y svg/onload no aparecen como etiquetas en el preview |
| Confiar en un rol o propietario enviado por el cliente permite elevar permisos o leer notas ajenas | DTOs sin esos campos; JSON estricto; rol User por servidor; `[Authorize]` y filtro por OwnerId de claims | Registro con role=Admin produce 400; User en panel Admin produce 403; operaciones sobre notas ajenas producen 404 |
| Guardar contraseñas o tokens reutilizables en claro agrava una filtración | PasswordHasher de Identity con sal y coste configurado; solo hash del token aleatorio | Misma contraseña genera hashes distintos y verificables; base de datos no contiene los bearer tokens en claro |
| Sesiones sin vencimiento o sin revocación | Vencimiento de 30 minutos y eliminación del hash al cerrar sesión | Token expirado y token revocado reciben 401 |
| Fuerza bruta de contraseñas | Bloqueo de 15 minutos tras cinco fallos y rate limiting por IP | Contraseña correcta se rechaza durante el bloqueo; exceso por IP produce 429 |
| Un cuerpo excesivo era convertido por el manejador genérico en error 500 | Reconocer `BadHttpRequestException` y conservar su código HTTP, sin detalles internos | Caso que inicialmente falló: POST de más de 16 KiB debe devolver 413 |
| El manejador de excepciones limpiaba las cabeceras de seguridad en la respuesta 413 | Aplicar cabeceras mediante `Response.OnStarting` | Caso de regresión verifica nosniff y no-store también en errores |

Los dos últimos fallos se observaron durante la ejecución de las pruebas de esta implementación y motivaron cambios concretos en `Program.cs` y `SecurityHeadersMiddleware.cs`.

## Límites de las comprobaciones

Las pruebas de XSS verifican el HTML devuelto y sus cabeceras; no ejecutan un navegador con JavaScript. La prueba de expiración adelanta el vencimiento de una sesión en la base de datos temporal, en vez de esperar 30 minutos. El rate limiter es de una instancia y no considera cabeceras reenviadas de proxies no configurados. No se han realizado pruebas de carga prolongadas, pentesting externo ni verificación completa de TLS. Los errores genéricos reducen información en respuestas, pero no se garantiza indistinguibilidad temporal completa del login.

## Participación de herramientas

El código, las reproducciones y la depuración descritos se realizaron con ChatGPT/Codex. La revisión con GitHub Copilot no se ha completado y no se atribuyen sugerencias ni resultados a esa herramienta. Esta distinción debe conservarse en el resumen de entrega hasta que exista una sesión real verificable.
