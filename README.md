# DNS Query Manual (Python)

Este es un script simple en Python que construye y envía manualmente una consulta DNS usando sockets UDP, sin depender de librerías externas como dnspython.
Está pensado para fines educativos o de experimentación con el protocolo DNS a bajo nivel.

## 🧩 Qué hace

Codifica un nombre de dominio en el formato DNS (por ejemplo, www.google.com → 3www6google3com0).

Construye un paquete de consulta DNS a mano (cabecera + pregunta).

Envía la consulta por UDP al puerto 53 del servidor DNS indicado.

Muestra la respuesta recibida en formato hexadecimal.

## ⚙️ Requisitos

Python 3.6 o superior

No necesita librerías externas

## 🚀 Uso

Edita las variables al inicio del archivo:

```bash
DNS_SERVER_IP = '192.203.230.10'  # Servidor DNS (puedes usar 8.8.8.8, 1.1.1.1, etc.)
DOMAIN_TO_RESOLVE = 'www.google.com'  # Dominio que quieras resolver
```

Ejecuta el script:

`python dns.py`


Si todo va bien, verás algo como:

```bash
Enviando consulta DNS para 'www.google.com' al servidor 8.8.8.8...
'1234abcd...'

--- Respuesta Recibida ---
De: ('8.8.8.8', 53)
Datos (hex): 1234abcd...
```

## ⚠️ Notas

El script no decodifica la respuesta DNS, solo la muestra en formato hexadecimal.

Usa UDP (no TCP).

Es ideal para aprender cómo funciona el protocolo DNS a nivel de bytes, no como un resolver completo.

## 🧠 Ideas de mejora

Implementar un parser para interpretar la respuesta DNS (por ejemplo, extraer la IP).

Añadir soporte para otros tipos de registro (AAAA, MX, etc.).

Permitir argumentos por línea de comandos.