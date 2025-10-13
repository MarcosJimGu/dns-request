import socket
import struct
import random

# --- Configuración ---
# IP del servidor DNS al que se le hará la consulta.
# Puedes usar un resolver público como '8.8.8.8' (Google) o '1.1.1.1' (Cloudflare).
# O la IP de un servidor raíz como '198.41.0.4' (a.root-servers.net).
DNS_SERVER_IP = '192.203.230.10' 

# Dominio que quieres resolver.
DOMAIN_TO_RESOLVE = 'www.google.com'

# --- Función para codificar el nombre de dominio ---
def encode_dns_name(domain):
    """
    Codifica un nombre de dominio al formato requerido por DNS (ej: www.google.com -> 3www6google3com0)
    """
    encoded = b''
    for part in domain.split('.'):
        encoded += struct.pack('B', len(part)) + part.encode('utf-8')
    return encoded + b'\x00' # Terminador nulo al final

# --- 1. Construcción del paquete de consulta DNS ---

# ID de la transacción (un número aleatorio de 16 bits)
transaction_id = random.randint(0, 65535)

# Flags (consulta estándar con recursión deseada sería 0x0100)
flags = 0x0000 

# Construcción de la cabecera DNS (12 bytes)
# !HHHHHH significa:
# ! -> Orden de bytes de red (big-endian)
# H -> Entero de 16 bits sin signo (unsigned short)
# Son 6 H porque la cabecera tiene 6 campos de 16 bits.
header = struct.pack('!HHHHHH', 
    transaction_id, # ID de la transacción
    flags,          # Flags
    1,              # Número de preguntas (siempre 1 para esta consulta)
    0,              # Número de respuestas (0 en una consulta)
    0,              # Número de registros de autoridad (0 en una consulta)
    0               # Número de registros adicionales (0 en una consulta)
)

# Construcción de la sección de la pregunta
# Nombre del dominio codificado
qname = encode_dns_name(DOMAIN_TO_RESOLVE)

# Tipo de consulta (A=1) y Clase de consulta (IN=1)
# !HH -> Dos enteros de 16 bits sin signo
qtype_qclass = struct.pack('!HH', 
    1, # QTYPE: 1 para un registro 'A' (dirección IPv4)
    1  # QCLASS: 1 para 'IN' (Internet)
)

# Paquete completo: se une la cabecera y la pregunta
dns_query_packet = header + qname + qtype_qclass

# --- 2. Envío de la solicitud y recepción de la respuesta ---

# Crear un socket UDP (AF_INET para IPv4, SOCK_DGRAM para UDP)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Es buena práctica establecer un tiempo de espera
sock.settimeout(2)

try:
    print(f"Enviando consulta DNS para '{DOMAIN_TO_RESOLVE}' al servidor {DNS_SERVER_IP}...\n'{dns_query_packet.hex()}'")
    
    # Enviar el paquete al servidor DNS en el puerto 53
    sock.sendto(dns_query_packet, (DNS_SERVER_IP, 53))
    
    # Recibir la respuesta (hasta 1024 bytes, que suele ser suficiente)
    response_data, server_address = sock.recvfrom(1024)
    
    print("\n--- Respuesta Recibida ---")
    print(f"De: {server_address}")
    # La respuesta viene en bytes, la mostramos en formato hexadecimal para que sea legible.
    print(f"Datos (hex): {response_data.hex()}")

except socket.timeout:
    print(f"Error: La solicitud a {DNS_SERVER_IP} ha expirado.")
except socket.gaierror:
    print(f"Error: No se pudo resolver la dirección del servidor DNS.")
finally:
    # Cerrar el socket
    sock.close()