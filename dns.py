import socket
import struct
import random

# --- Configuración ---
# IP del servidor DNS al que se le hará la consulta.
# Para obtener una respuesta completa de varias secciones (Autoridad, Adicionales)
# es bueno usar un servidor raíz o un servidor que no sea recursivo.
# '198.41.0.4' es a.root-servers.net.
# Si quieres una respuesta simple, usa '8.8.8.8' (Google Public DNS).
DNS_SERVER_IP = '216.239.36.10' 

# Dominio que quieres resolver.
DOMAIN_TO_RESOLVE = 'www.google.com'

# Diccionario para mapear el código de tipo (QTYPE) a un nombre legible
RTYPE_MAP = {
    1: 'A',      # Dirección IPv4
    2: 'NS',     # Servidor de Nombres
    5: 'CNAME',  # Nombre Canónico (Alias)
    6: 'SOA',    # Autoridad de Inicio de Zona
    12: 'PTR',   # Puntero (para búsquedas inversas)
    15: 'MX',    # Intercambiador de Correo
    16: 'TXT',    # Texto (Información descriptiva)
    28: 'AAAA',   # Dirección IPv6
    255: 'ANY'   # Cualquier tipo de registro
}

# --- Función para codificar el nombre de dominio ---
def encode_dns_name(domain):
    """
    Codifica un nombre de dominio al formato requerido por DNS (ej: www.google.com -> 3www6google3com0)
    """
    encoded = b''
    for part in domain.split('.'):
        encoded += struct.pack('B', len(part)) + part.encode('utf-8')
    return encoded + b'\x00' # Terminador nulo al final

# --- Función para decodificar el nombre de dominio desde la respuesta (maneja compresión) ---
def decode_dns_name(response_data, offset):
    parts = []
    current_offset = offset
    jumps = 0 # Contador para evitar bucles infinitos por punteros mal formados
    
    while True:
        if jumps > 10: raise Exception("Demasiados saltos de compresión, posible bucle.")
        
        length = response_data[current_offset]
        
        # Si los dos primeros bits son 11 (0xc0), es un puntero (compresión)
        if (length & 0xC0) == 0xC0:
            # Los 14 bits restantes son el offset (puntero)
            pointer_offset = struct.unpack('!H', response_data[current_offset:current_offset+2])[0] & 0x3FFF
            
            # Decodificamos el resto del nombre desde el puntero (salto)
            # Nota: el offset final para la función que llama es justo después de este puntero
            if jumps == 0:
                offset += 2
                
            parts.extend(decode_dns_name(response_data, pointer_offset)[0].split('.'))
            jumps += 1
            break # Terminamos de decodificar el nombre actual
        
        # Si la longitud es 0, es el final del nombre de dominio
        elif length == 0:
            if jumps == 0:
                offset += 1
            break
        
        # Si no es un puntero, es una etiqueta de texto normal
        else:
            current_offset += 1
            label = response_data[current_offset:current_offset+length].decode('utf-8', errors='ignore')
            parts.append(label)
            current_offset += length
            if jumps == 0:
                offset = current_offset

    return ".".join(parts), offset

# --- FUNCIÓN AUXILIAR PARA PARSEAR CUALQUIER REGISTRO DE RECURSOS (RR) ---
def parse_resource_record(response_data, offset):
    """
    Parsea un Registro de Recurso (RR) de las secciones Answer, Authority o Additional.
    Devuelve la información del RR y el nuevo offset.
    """
    # El nombre puede estar comprimido, se decodifica
    domain, offset = decode_dns_name(response_data, offset)
    
    # Unpack de tipo, clase, TTL y longitud de datos (10 bytes)
    try:
        rtype, rclass, rttl, rdlength = struct.unpack('!HHIH', response_data[offset:offset+10])
    except struct.error:
        print("Error: Paquete DNS incompleto o malformado.")
        return None, len(response_data)
        
    offset += 10
    
    # Preparamos el diccionario de salida para el RR
    rtype_name = RTYPE_MAP.get(rtype, f'Tipo {rtype}')
    rdata = {}
    rdata['Dominio_Pregunta'] = domain
    rdata['Tipo'] = rtype_name
    rdata['Clase'] = f"{rclass} (IN)"
    rdata['TTL'] = f"{rttl} segundos"
    rdata['RData_Length'] = rdlength
    
    # Interpretamos los datos (RDATA) según el tipo
    try:
        if rtype == 1: # Tipo A (IPv4 Address)
            ip_address_bytes = response_data[offset:offset+rdlength]
            rdata['Valor'] = socket.inet_ntoa(ip_address_bytes)
        
        elif rtype == 28: # Tipo AAAA (IPv6 Address)
            ip_address_bytes = response_data[offset:offset+rdlength]
            # Usamos inet_ntop para IPv6
            rdata['Valor'] = socket.inet_ntop(socket.AF_INET6, ip_address_bytes)
            
        elif rtype in [2, 5]: # Tipos NS (Name Server) o CNAME (Canonical Name)
            # Estos tipos contienen otro nombre de dominio. Lo decodificamos desde el RDATA.
            target_name, _ = decode_dns_name(response_data, offset)
            rdata['Valor'] = target_name
        
        elif rtype == 15: # Tipo MX (Mail Exchanger)
            # MX tiene un campo de Prioridad de 2 bytes, seguido del nombre del servidor.
            preference = struct.unpack('!H', response_data[offset:offset+2])[0]
            mail_exchanger, _ = decode_dns_name(response_data, offset + 2)
            rdata['Prioridad'] = preference
            rdata['Valor'] = mail_exchanger

        elif rtype == 16: # Tipo TXT (Texto)
            # El campo TXT contiene varias cadenas de texto, cada una precedida por su longitud
            txt_offset = offset
            text_parts = []
            while txt_offset < offset + rdlength:
                text_len = response_data[txt_offset]
                txt_offset += 1
                text_content = response_data[txt_offset:txt_offset + text_len].decode('utf-8', errors='ignore')
                text_parts.append(text_content)
                txt_offset += text_len
            rdata['Valor'] = " ".join(text_parts)
        
        else:
            rdata['Valor'] = response_data[offset:offset+rdlength].hex() # Datos sin interpretar

    except Exception as e:
        rdata['Error'] = f"Error al decodificar RDATA: {e}"
    
    # Avanzamos el offset después del RDATA para el siguiente RR
    new_offset = offset + rdlength
    return rdata, new_offset

# --- FUNCIÓN PRINCIPAL PARA INTERPRETAR LA RESPUESTA DNS ---
def parse_dns_response(response_data):
    # 1. Desglosar la cabecera (primeros 12 bytes)
    header = struct.unpack('!HHHHHH', response_data[:12])
    res_id = header[0]
    res_flags = header[1]
    res_qdcount = header[2] # Número de preguntas
    res_ancount = header[3] # Número de respuestas
    res_nscount = header[4] # Número de registros de autoridad
    res_arcount = header[5] # Número de registros adicionales

    # Desglose de los FLAGS (16 bits)
    qr = (res_flags >> 15) & 0x1       # Query (0) / Response (1)
    opcode = (res_flags >> 11) & 0xF   # Operation Code (0=Standard Query)
    aa = (res_flags >> 10) & 0x1       # Authoritative Answer
    tc = (res_flags >> 9) & 0x1        # Truncation
    rd = (res_flags >> 8) & 0x1        # Recursion Deseada
    ra = (res_flags >> 7) & 0x1        # Recursion Available
    z = (res_flags >> 4) & 0x7         # Reserved (debe ser 0)
    rcode = res_flags & 0xF            # Response Code (0=No Error, 3=NXDomain)
    
    print("\n" + "="*50)
    print("           ESTRUCTURA DEL MENSAJE DNS")
    print("="*50)
    
    # IMPRESIÓN DE LA CABECERA
    print("\n--- 1. CABECERA (HEADER) ---")
    print(f"  [ID de Transacción]: {res_id}")
    print(f"  [Flags Binario]: {res_flags:#018b}")
    print(f"  [QR (Tipo)]: {'Respuesta (1)' if qr else 'Consulta (0)'}")
    print(f"  [Opcode]: {opcode} (Consulta Estándar)")
    print(f"  [AA (Autoridad)]: {'Sí (1)' if aa else 'No (0)'} (Respuesta de servidor autoritativo)")
    print(f"  [TC (Truncado)]: {'Sí (1)' if tc else 'No (0)'} (Mensaje cortado)")
    print(f"  [RD (Recursión Deseada)]: {'Sí (1)' if rd else 'No (0)'}")
    print(f"  [RA (Recursión Disponible)]: {'Sí (1)' if ra else 'No (0)'}")
    print(f"  [RCODE]: {rcode} ({'NOERROR (0)' if rcode == 0 else 'ERROR'})")
    print(f"  [QDCOUNT (Preguntas)]: {res_qdcount}")
    print(f"  [ANCOUNT (Respuestas)]: {res_ancount}")
    print(f"  [NSCOUNT (Autoridad)]: {res_nscount}")
    print(f"  [ARCOUNT (Adicionales)]: {res_arcount}")
    
    # El offset inicial para leer es justo después de la cabecera
    offset = 12

    # 2. SECCIÓN DE PREGUNTA (QUESTION)
    print("\n--- 2. SECCIÓN DE PREGUNTA (QUESTION) ---")
    for i in range(res_qdcount):
        domain, offset = decode_dns_name(response_data, offset)
        qtype, qclass = struct.unpack('!HH', response_data[offset:offset+4])
        offset += 4
        qtype_name = RTYPE_MAP.get(qtype, f'Tipo {qtype}')
        print(f"  Pregunta {i+1}:")
        print(f"    [QNAME]: {domain}")
        print(f"    [QTYPE]: {qtype_name} (Código: {qtype})")
        print(f"    [QCLASS]: {qclass} (IN - Internet)")
        
    # 3. SECCIÓN DE RESPUESTAS (ANSWER)
    print("\n--- 3. SECCIÓN DE RESPUESTAS (ANSWER) ---")
    if res_ancount == 0:
        print("  Sin registros de respuesta (ANCOUNT = 0).")
    
    for i in range(res_ancount):
        rr, offset = parse_resource_record(response_data, offset)
        if rr is None: break
        print(f"  Registro de Recurso (RR) {i+1} (Respuesta):")
        for key, value in rr.items():
            print(f"    [{key}]: {value}")
        print("-" * 20)

    # 4. SECCIÓN DE AUTORIDAD (AUTHORITY)
    print("\n--- 4. SECCIÓN DE AUTORIDAD (AUTHORITY) ---")
    if res_nscount == 0:
        print("  Sin registros de autoridad (NSCOUNT = 0).")
        
    for i in range(res_nscount):
        rr, offset = parse_resource_record(response_data, offset)
        if rr is None: break
        print(f"  Registro de Recurso (RR) {i+1} (Autoridad):")
        for key, value in rr.items():
            print(f"    [{key}]: {value}")
        print("-" * 20)

    # 5. SECCIÓN ADICIONAL (ADDITIONAL)
    print("\n--- 5. SECCIÓN ADICIONAL (ADDITIONAL) ---")
    if res_arcount == 0:
        print("  Sin registros adicionales (ARCOUNT = 0).")
        
    for i in range(res_arcount):
        rr, offset = parse_resource_record(response_data, offset)
        if rr is None: break
        print(f"  Registro de Recurso (RR) {i+1} (Adicional):")
        for key, value in rr.items():
            print(f"    [{key}]: {value}")
        print("-" * 20)
    
    print("\n" + "="*50)


# --- 1. Construcción del paquete de consulta DNS ---

# ID de la transacción (un número aleatorio de 16 bits)
transaction_id = random.randint(0, 65535)

# Flags (recursión deseada activada: 0x0100)
# Queremos que un resolver nos dé la respuesta final (RD = 1)
flags = 0x0100 

# Construcción de la cabecera DNS (12 bytes)
header = struct.pack('!HHHHHH', 
    transaction_id, # ID de la transacción
    flags,          # Flags (Recursión Deseada activada)
    1,              # Número de preguntas (QDCOUNT)
    0,              # Número de respuestas (ANCOUNT)
    0,              # Número de registros de autoridad (NSCOUNT)
    0               # Número de registros adicionales (ARCOUNT)
)

# Construcción de la sección de la pregunta
# Nombre del dominio codificado
qname = encode_dns_name(DOMAIN_TO_RESOLVE)

# Tipo de consulta (A=1) y Clase de consulta (IN=1)
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
sock.settimeout(3)

try:
    print(f"Enviando consulta DNS para '{DOMAIN_TO_RESOLVE}' al servidor {DNS_SERVER_IP}...")
    
    # Enviar el paquete al servidor DNS en el puerto 53
    sock.sendto(dns_query_packet, (DNS_SERVER_IP, 53))
    
    # Recibir la respuesta (hasta 512 bytes es el límite UDP, pero aceptamos hasta 1024)
    response_data, server_address = sock.recvfrom(1024)
    
    print("\n--- Respuesta Recibida ---")
    print(f"De: {server_address}")
    # print(f"Datos (hex): {response_data.hex()}") # Descomentar para ver los bytes
    
    parse_dns_response(response_data)

except socket.timeout:
    print(f"Error: La solicitud a {DNS_SERVER_IP} ha expirado. Intenta con un servidor más rápido (ej: 8.8.8.8) si estás usando un servidor raíz.")
except socket.gaierror:
    print(f"Error: No se pudo resolver la dirección del servidor DNS.")
except Exception as e:
    print(f"Error general durante la ejecución: {e}")
finally:
    # Cerrar el socket
    sock.close()