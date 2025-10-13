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

# --- NUEVA FUNCIÓN: Para decodificar el nombre de dominio desde la respuesta ---
# Esta es más compleja que la de codificar porque debe manejar "punteros de compresión".
def decode_dns_name(response_data, offset):
    parts = []
    original_offset = offset
    jumps = 0 # Para evitar bucles infinitos por punteros mal formados
    
    while True:
        if jumps > 10: raise Exception("Demasiados saltos de compresión, posible bucle.")
        
        length = response_data[offset]
        
        # Si los dos primeros bits son 11 (0xc0), es un puntero
        if (length & 0xC0) == 0xC0:
            # El puntero son los 14 bits restantes, que apuntan a una posición en el paquete
            pointer_offset = struct.unpack('!H', response_data[offset:offset+2])[0] & 0x3FFF
            # Llamada recursiva para decodificar el nombre desde la nueva posición
            parts.extend(decode_dns_name(response_data, pointer_offset)[0].split('.'))
            offset += 2 # El puntero ocupa 2 bytes
            # Si es la primera vez que saltamos, actualizamos el offset final
            if jumps == 0:
                original_offset = offset
            return ".".join(parts), original_offset
        
        # Si la longitud es 0, es el final del nombre de dominio
        elif length == 0:
            offset += 1
            break
        
        # Si no es un puntero, es una etiqueta de texto normal
        else:
            offset += 1
            label = response_data[offset:offset+length].decode('utf-8', errors='ignore')
            parts.append(label)
            offset += length

    # Si no hubo saltos, el nuevo offset es el actual
    final_offset = offset if jumps == 0 else original_offset
    return ".".join(parts), final_offset


# --- NUEVA FUNCIÓN: Para interpretar toda la respuesta DNS ---
def parse_dns_response(response_data):
    # 1. Desglosar la cabecera (primeros 12 bytes)
    header = struct.unpack('!HHHHHH', response_data[:12])
    res_id = header[0]
    res_flags = header[1]
    res_qdcount = header[2] # Número de preguntas
    res_ancount = header[3] # Número de respuestas
    res_nscount = header[4] # Número de registros de autoridad
    res_arcount = header[5] # Número de registros adicionales

    print("\n--- Cabecera DNS ---")
    print(f"ID de Transacción: {res_id}")
    print(f"Flags: {res_flags:#018b}") # Mostramos los flags en binario para ver los bits
    print(f"Preguntas: {res_qdcount}")
    print(f"Respuestas: {res_ancount}")
    print(f"Servidores de Autoridad: {res_nscount}")
    print(f"Registros Adicionales: {res_arcount}\n")
    
    # El offset inicial para leer es justo después de la cabecera
    offset = 12

    # 2. Desglosar la(s) pregunta(s)
    print("--- Sección de Pregunta ---")
    for _ in range(res_qdcount):
        domain, offset = decode_dns_name(response_data, offset)
        qtype, qclass = struct.unpack('!HH', response_data[offset:offset+4])
        offset += 4
        print(f"Dominio: {domain}, Tipo: {qtype}, Clase: {qclass}\n")

    # 3. Desglosar las respuestas
    print("--- Sección de Respuestas (Registros 'A') ---")
    if res_ancount == 0:
        print("No se encontraron respuestas.")
    
    for _ in range(res_ancount):
        domain, offset = decode_dns_name(response_data, offset)
        # Unpack de tipo, clase, TTL y longitud de datos
        rtype, rclass, rttl, rdlength = struct.unpack('!HHIH', response_data[offset:offset+10])
        offset += 10
        
        # Interpretamos los datos (RDATA) según el tipo
        # Nos centraremos en el tipo 1 (A, para IPv4) que es el más común
        if rtype == 1: # Tipo A
            ip_address_bytes = response_data[offset:offset+rdlength]
            ip_address = socket.inet_ntoa(ip_address_bytes)
            print(f"Dominio: {domain}")
            print(f"  -> Tipo: A (Dirección IPv4)")
            print(f"  -> TTL: {rttl} segundos")
            print(f"  -> IP: {ip_address}")
        # Se podrían añadir más 'if' para otros tipos (CNAME, MX, etc.)
        else:
            print(f"Dominio: {domain}")
            print(f"  -> Tipo: {rtype} (No interpretado en este script)")
            print(f"  -> TTL: {rttl} segundos")

        # Avanzamos el offset a la siguiente respuesta
        offset += rdlength

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
    print(f"\nResumen:\n")
    parse_dns_response(response_data)

except socket.timeout:
    print(f"Error: La solicitud a {DNS_SERVER_IP} ha expirado.")
except socket.gaierror:
    print(f"Error: No se pudo resolver la dirección del servidor DNS.")
finally:
    # Cerrar el socket
    sock.close()