import socket
import struct
import secrets
import binascii

def get_stun_response():
    # Configuración del servidor Google
    STUN_SERVER = 'stun.l.google.com'
    STUN_PORT = 3478
    
    # Constantes STUN (RFC 5389)
    MAGIC_COOKIE = 0x2112A442
    BINDING_REQUEST = 0x0001
    
    # Crear socket UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)

    try:
        sock.bind(('0.0.0.0', 2025))
        # --- 1. CONSTRUCCIÓN DE LA PETICIÓN ---
        # Header: Type (2B) | Length (2B) | Magic Cookie (4B) | Transaction ID (12B)
        trans_id = secrets.token_bytes(12)
        # Empaquetamos: !H (unsigned short), I (unsigned int), 12s (12 bytes string)
        packet = struct.pack('!HH I 12s', BINDING_REQUEST, 0, MAGIC_COOKIE, trans_id)

        print("-" * 50)
        print(f"1. ENVIANDO (Binding Request) a {STUN_SERVER}:{STUN_PORT}")
        print(f"   Hex Enviado: {binascii.hexlify(packet, ' ').decode().upper()}")
        print("-" * 50)

        sock.sendto(packet, (STUN_SERVER, STUN_PORT))

        # --- 2. RECEPCIÓN DE LA RESPUESTA ---
        data, addr = sock.recvfrom(2048)
        
        print(f"2. RECIBIDO (Binding Response) de {addr}")
        print(f"   Hex Recibido: {binascii.hexlify(data, ' ').decode().upper()}")
        print("-" * 50)

        # --- 3. PARSEO (DECODIFICACIÓN) ---
        print("3. TRADUCCIÓN (Parseo byte a byte)")
        
        # Desempaquetamos la cabecera (primeros 20 bytes)
        msg_type, msg_len, magic, recv_trans_id = struct.unpack('!HH I 12s', data[:20])
        
        print(f"   > Header Type: {hex(msg_type)} (Debe ser 0x101 para Success)")
        print(f"   > Body Length: {msg_len} bytes")
        
        if recv_trans_id != trans_id:
            print("   [!] Error: El Transaction ID no coincide.")
            return

        # Iterar sobre los atributos (Payload después del byte 20)
        # Buscamos el atributo XOR-MAPPED-ADDRESS (Tipo 0x0020)
        idx = 20
        while idx < len(data):
            # Leemos Tipo (2 bytes) y Longitud (2 bytes) del atributo actual
            attr_type, attr_len = struct.unpack('!HH', data[idx:idx+4])
            
            # 0x0020 es XOR-MAPPED-ADDRESS (El estándar actual)
            # 0x0001 es MAPPED-ADDRESS (Versión antigua, Google a veces lo usa)
            if attr_type == 0x0020:
                print(f"   > Atributo encontrado: XOR-MAPPED-ADDRESS (0x0020)")
                
                # El valor del atributo empieza después del header del atributo (+4)
                value_start = idx + 4
                
                # Estructura XOR-MAPPED: Reserved(1B), Family(1B), X-Port(2B), X-Address(4B)
                _, family, x_port, x_ip = struct.unpack('!BB H I', data[value_start:value_start+8])
                
                print(f"     - Familia: {'IPv4' if family == 0x01 else 'IPv6'}")
                print(f"     - Puerto XOR (Raw): {hex(x_port)}")
                print(f"     - IP XOR (Raw):     {hex(x_ip)}")
                
                # --- LÓGICA DE DECODIFICACIÓN XOR ---
                # Puerto Real = PuertoXOR ^ (MagicCookie >> 16)
                # IP Real     = IPXOR     ^ MagicCookie
                
                real_port = x_port ^ (MAGIC_COOKIE >> 16)
                real_ip_int = x_ip ^ MAGIC_COOKIE
                
                # Convertir entero IP a string (ej. 192.168.1.1)
                real_ip_str = socket.inet_ntoa(struct.pack('!I', real_ip_int))
                
                print("\n   RESULTADO FINAL:")
                print(f"   >> IP PÚBLICA:   {real_ip_str}")
                print(f"   >> PUERTO NAT:   {real_port}")
                break
            
            # Avanzar al siguiente atributo
            idx += 4 + attr_len

    except socket.timeout:
        print("Timeout: No se recibió respuesta.")
    except Exception as e:
        print(f"Error parseando: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    get_stun_response()