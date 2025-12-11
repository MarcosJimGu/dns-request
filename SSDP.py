import socket
import re
from urllib.parse import urlparse

# --- CONFIGURACIÓN ---
ROUTER_IP = "192.168.1.1"
PORT = 8008             # El puerto a manipular
PROTOCOL = "TCP"        # TCP o UDP
ACTION = "CLOSE"         # Opciones: "OPEN" o "CLOSE"
# ---------------------

def get_local_ip():
    """Obtiene la IP local que conecta con el router."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ROUTER_IP, 80))
        ip = s.getsockname()[0]
    except:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip

def get_control_url():
    """
    1. Envía SSDP Unicast directo al router.
    2. Obtiene la URL del XML.
    3. Descarga el XML y extrae la URL de Control real.
    """
    print(f"[*] Buscando router en {ROUTER_IP} (Modo Unicast)...")
    
    # 1. SSDP Directo (Unicast)
    msg = (
        'M-SEARCH * HTTP/1.1\r\n'
        f'HOST: {ROUTER_IP}:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'ST: urn:schemas-upnp-org:service:WANIPConnection:1\r\n'
        'MX: 2\r\n\r\n'
    )
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    
    xml_url = None
    try:
        sock.sendto(msg.encode(), (ROUTER_IP, 1900))
        while True:
            data, _ = sock.recvfrom(4096)
            resp = data.decode(errors='ignore')
            loc = re.search(r'LOCATION: (http://.+)', resp, re.IGNORECASE)
            if loc:
                xml_url = loc.group(1).strip()
                break
    except socket.timeout:
        print("[!] Timeout: El router no respondió al descubrimiento.")
        return None, None
    finally:
        sock.close()

    if not xml_url: return None, None

    print(f"[*] XML descriptor hallado: {xml_url}")

    # 2. Descargar XML y buscar ControlURL
    parsed = urlparse(xml_url)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((parsed.hostname, parsed.port))
        req = f"GET {parsed.path} HTTP/1.1\r\nHost: {parsed.hostname}:{parsed.port}\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        
        xml_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            xml_data += chunk
        s.close()
        
        content = xml_data.decode(errors='ignore')
        
        # Buscar servicio WANIPConnection y su controlURL
        # Priorizamos WANIPConnection:1
        service_type = "urn:schemas-upnp-org:service:WANIPConnection:1"
        if service_type not in content:
            # Fallback a v2 o PPP
            if "WANIPConnection:2" in content: service_type = "urn:schemas-upnp-org:service:WANIPConnection:2"
            elif "WANPPPConnection:1" in content: service_type = "urn:schemas-upnp-org:service:WANPPPConnection:1"
        
        # Extracción sucia pero efectiva de la URL de control asociada al servicio
        parts = content.split(service_type)
        if len(parts) > 1:
            block = parts[1][:2000] # Miramos el bloque siguiente
            c_start = block.find("<controlURL>")
            c_end = block.find("</controlURL>")
            if c_start != -1:
                ctrl_path = block[c_start+12:c_end].strip()
                
                # Reconstruir URL absoluta
                if not ctrl_path.startswith("http"):
                    if not ctrl_path.startswith("/"): ctrl_path = "/" + ctrl_path
                    full_url = f"http://{parsed.hostname}:{parsed.port}{ctrl_path}"
                    return full_url, service_type
                return ctrl_path, service_type

    except Exception as e:
        print(f"[!] Error analizando XML: {e}")
    
    return None, None

def execute_soap(url, service, action, local_ip):
    """Envía la petición SOAP (Add o Delete)."""
    parsed = urlparse(url)
    
    if action == "OPEN": # <NewLeaseDuration> indica 5 minutos de apertura de puerto.
        print(f"[*] ABRIENDO puerto {PORT} ({PROTOCOL}) hacia {local_ip}...")
        method = "AddPortMapping"
        args = f"""
        <NewRemoteHost></NewRemoteHost>
        <NewExternalPort>{PORT}</NewExternalPort>
        <NewProtocol>{PROTOCOL}</NewProtocol>
        <NewInternalPort>{PORT}</NewInternalPort>
        <NewInternalClient>{local_ip}</NewInternalClient>
        <NewEnabled>1</NewEnabled>
        <NewPortMappingDescription>PythonRule</NewPortMappingDescription>
        <NewLeaseDuration>300</NewLeaseDuration>
        """
    else: # CLOSE
        print(f"[*] CERRANDO puerto {PORT} ({PROTOCOL})...")
        method = "DeletePortMapping"
        args = f"""
        <NewRemoteHost></NewRemoteHost>
        <NewExternalPort>{PORT}</NewExternalPort>
        <NewProtocol>{PROTOCOL}</NewProtocol>
        """

    soap_body = f"""<?xml version="1.0"?>
    <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
    <s:Body>
    <u:{method} xmlns:u="{service}">
    {args}
    </u:{method}>
    </s:Body>
    </s:Envelope>"""

    headers = (
        f"POST {parsed.path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        f"Content-Type: text/xml; charset=\"utf-8\"\r\n"
        f"Content-Length: {len(soap_body)}\r\n"
        f"SOAPAction: \"{service}#{method}\"\r\n"
        "Connection: close\r\n\r\n"
    )

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((parsed.hostname, parsed.port))
        s.send((headers + soap_body).encode())
        resp = s.recv(4096).decode(errors='ignore')
        s.close()

        if "200 OK" in resp:
            print(f"[EXITO] Operación {action} realizada correctamente.")
        elif "500 Internal" in resp:
            print(f"[FALLO] Error 500. Posibles causas:")
            if action == "OPEN": print("- El puerto ya está en uso.\n- UPnP desactivado.")
            if action == "CLOSE": print("- El puerto no estaba abierto o no fue creado por UPnP.")
        else:
            print(f"[?] Respuesta inesperada: {resp[:100]}...")
    except Exception as e:
        print(f"[!] Error de conexión SOAP: {e}")

if __name__ == "__main__":
    local_ip = get_local_ip()
    url, service = get_control_url()
    
    if url and service:
        execute_soap(url, service, ACTION, local_ip)
    else:
        print("[!] No se pudo obtener la información de control del router.")