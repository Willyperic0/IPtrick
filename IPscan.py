import socket
import os
import platform
import threading
import ipaddress

def get_local_network():
    """Obtiene la red local automáticamente."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = local_ip.rsplit('.', 1)[0] + ".0/24"
        return network
    except Exception as e:
        print(f"Error al obtener la red local: {e}")
        return None

def ping(ip):
    """Realiza un ping a una dirección IP y devuelve True si está activa."""
    system = platform.system().lower()
    param = "-n 1" if system == "windows" else "-c 1"
    command = f"ping {param} -w 500 {ip} >nul 2>&1" if system == "windows" else f"ping {param} -W 1 {ip} >/dev/null 2>&1"
    return os.system(command) == 0

def scan_network(network):
    """Escanea la red en busca de dispositivos activos usando ping."""
    devices = []
    for ip in ipaddress.IPv4Network(network, strict=False):
        if ping(str(ip)):
            devices.append(str(ip))
    return devices

def start_scan():
    """Función para iniciar el escaneo en un hilo separado."""
    network = get_local_network()
    if not network:
        print("No se pudo determinar la red local.")
        return
    
    print(f"Escaneando la red {network}...")
    devices = scan_network(network)
    print("\nDispositivos conectados:")
    for device in devices:
        print(device)

if __name__ == "__main__":
    scan_thread = threading.Thread(target=start_scan)
    scan_thread.start()
    scan_thread.join()
    print("\nEscaneo finalizado.")