import socket
import platform
import subprocess
import re
import threading
from datetime import datetime
import psutil
import uuid
import ipaddress
import os
import requests
import time

class EnhancedMACVendor:
    def __init__(self):
        self.cache = {}
        self.request_delay = 0.3
        # Base de datos extendida específicamente para dispositivos comunes
        self.extended_local_db = self._build_extended_database()
    
    def _build_extended_database(self):
        """Base de datos local extendida con fabricantes comunes."""
        return {
            # Xiaomi - prefijos comunes
            '8C:BE:BE': 'Xiaomi Communications',
            '64:09:80': 'Xiaomi Communications', 
            '34:AF:2C': 'Xiaomi Communications',
            '80:5E:0C': 'Xiaomi Communications',
            '4C:49:E3': 'Xiaomi Communications',
            '0C:1D:AF': 'Xiaomi Communications',
            '60:F4:45': 'Xiaomi Communications',
            '28:ED:6A': 'Xiaomi Communications',
            '8C:85:80': 'Xiaomi Communications',
            'DC:53:7C': 'Xiaomi Communications',
            'F8:8C:21': 'Xiaomi Communications',
            'FC:64:3A': 'Xiaomi Communications',
            '8E:62:3F': 'Xiaomi Communications',  # TU DISPOSITIVO ESPECÍFICO
            
            # Tu red específica
            '08:40:F3': 'Tenda Technology',  # Router
            'F0:2F:74': 'ASUSTek Computer',  # Tu PC
            
            # Fabricantes comunes
            '00:1B:44': 'Google',
            '00:1D:0F': 'Apple',
            '00:24:36': 'Cisco',
            '00:26:B0': 'Dell',
            '00:1A:11': 'TP-Link',
            '00:1E:8C': 'Netgear',
            '00:22:3F': 'ASUS',
            '00:23:69': 'Huawei',
            '00:25:9C': 'Samsung',
            '00:26:5A': 'LG',
            '14:CC:20': 'Sony',
            '18:60:24': 'Amazon',
            '28:16:2E': 'Xiaomi',
            '30:8C:FB': 'LG Electronics',
            '34:E2:FD': 'Apple',
            '3C:5A:B4': 'Google',
            '44:65:0D': 'TP-Link',
            '50:C7:BF': 'TP-Link',
            '60:A4:4C': 'ASUS',
            '74:EA:3A': 'TP-Link',
            '84:38:35': 'Huawei',
            'A4:34:D9': 'Google',
            'B8:27:EB': 'Raspberry Pi',
            'C0:56:27': 'Belkin',
            'D8:50:E6': 'ASUS',
            'DC:A4:CA': 'Apple',
            'F4:F5:24': 'Google',
        }
    
    def get_vendor(self, mac):
        """Sistema mejorado de detección de fabricantes."""
        if mac in self.cache:
            return self.cache[mac]
        
        # Primero verificar base de datos local extendida
        local_result = self._check_local_database(mac)
        if local_result != "Fabricante desconocido":
            self.cache[mac] = local_result
            return local_result
        
        # Luego intentar con API online
        api_result = self._check_online_api(mac)
        if api_result not in ["No encontrado en API", "Timeout en API", "Sin conexión a API"] and not api_result.startswith("Error en API"):
            self.cache[mac] = api_result
            return api_result
        
        # Si todo falla, usar base local básica
        basic_local = self._check_basic_local(mac)
        self.cache[mac] = basic_local
        return basic_local
    
    def _check_local_database(self, mac):
        """Verifica la base de datos local extendida."""
        try:
            mac_clean = mac.upper().replace('-', ':')
            oui = mac_clean[:8]  # Primeros 3 bytes
            return self.extended_local_db.get(oui, "Fabricante desconocido")
        except:
            return "Fabricante desconocido"
    
    def _check_online_api(self, mac):
        """Consulta la API online."""
        try:
            mac_clean = mac.upper().replace('-', ':').replace('.', '')
            mac_oui = mac_clean[:6]
            
            # Intentar con múltiples APIs
            apis = [
                f"https://api.macvendors.com/{mac_oui}",
                f"https://macvendors.co/api/v2/{mac_oui}/json"
            ]
            
            for api_url in apis:
                try:
                    response = requests.get(api_url, timeout=3)
                    if response.status_code == 200:
                        if 'macvendors.co' in api_url:
                            # Procesar respuesta JSON
                            data = response.json()
                            vendor = data.get('result', {}).get('company', 'No encontrado')
                        else:
                            # Procesar respuesta de texto plano
                            vendor = response.text.strip()
                        
                        if vendor and vendor != "No encontrado":
                            print(f"  ✅ API: {mac} -> {vendor}")
                            return vendor
                except:
                    continue
            
            print(f"  ❌ API: No encontrado para {mac}")
            return "No encontrado en API"
                
        except requests.exceptions.Timeout:
            print(f"  ⏰ API: Timeout para {mac}")
            return "Timeout en API"
        except requests.exceptions.ConnectionError:
            print(f"  🌐 API: Sin conexión para {mac}")
            return "Sin conexión a API"
        except Exception as e:
            print(f"  ❌ API: Error para {mac} - {str(e)}")
            return f"Error en API: {str(e)}"
        finally:
            time.sleep(self.request_delay)
    
    def _check_basic_local(self, mac):
        """Base de datos local básica como último recurso."""
        try:
            mac_clean = mac.upper().replace('-', ':')
            oui = mac_clean[:8]
            
            # Detección por patrones comunes
            if oui.startswith('8C:BE:BE') or oui.startswith('64:09:80') or oui.startswith('34:AF:2C'):
                return "Xiaomi (detectado por patrón)"
            elif oui.startswith('00:1D:0F') or oui.startswith('34:E2:FD') or oui.startswith('DC:A4:CA'):
                return "Apple (detectado por patrón)"
            elif oui.startswith('00:1B:44') or oui.startswith('3C:5A:B4') or oui.startswith('A4:34:D9'):
                return "Google (detectado por patrón)"
            elif oui.startswith('00:25:9C') or oui.startswith('5C:0A:5B') or oui.startswith('64:77:91'):
                return "Samsung (detectado por patrón)"
            elif oui.startswith('00:23:69') or oui.startswith('84:38:35') or oui.startswith('00:1E:10'):
                return "Huawei (detectado por patrón)"
            else:
                return "Fabricante desconocido"
        except:
            return "Fabricante desconocido"

class AdvancedNetworkScanner:
    def __init__(self):
        self.local_ip = self.get_local_ip()
        self.network = self.get_local_network()
        self.devices = []
        self.mac_vendor_lookup = EnhancedMACVendor()
        
    def get_local_ip(self):
        """Obtiene la IP local del equipo."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "No disponible"
    
    def get_local_network(self):
        """Obtiene la red local."""
        if self.local_ip != "No disponible":
            network = self.local_ip.rsplit('.', 1)[0] + ".0/24"
            return network
        return None
    
    def get_local_mac_address(self):
        """Obtiene la MAC de la interfaz local de forma confiable."""
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == self.local_ip:
                        for addr2 in addrs:
                            if addr2.family == psutil.AF_LINK:
                                mac = addr2.address.upper()
                                mac = mac.replace('-', ':')
                                return mac
            return "No disponible"
        except Exception as e:
            return f"Error: {str(e)}"
    
    def get_system_info(self):
        """Obtiene información del sistema local."""
        try:
            system = platform.system()
            hostname = socket.gethostname()
            mac = self.get_local_mac_address()
            interface = self.get_network_interface()
            gateway = self.get_default_gateway()
            
            return {
                'sistema': system,
                'hostname': hostname,
                'mac_local': mac,
                'ip_local': self.local_ip,
                'interfaz': interface,
                'gateway': gateway,
                'red': self.network
            }
        except Exception as e:
            return f"Error: {e}"
    
    def get_network_interface(self):
        """Obtiene la interfaz de red activa."""
        try:
            for interface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address == self.local_ip:
                        return interface
            return "No disponible"
        except:
            return "No disponible"
    
    def get_default_gateway(self):
        """Obtiene el gateway predeterminado."""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run("ipconfig", capture_output=True, text=True, shell=True)
                lines = result.stdout.split('\n')
                for line in lines:
                    if "Default Gateway" in line or "Puerta de enlace predeterminada" in line:
                        gateway_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                        if gateway_match:
                            return gateway_match.group(1)
            else:
                result = subprocess.run("ip route | grep default", capture_output=True, text=True, shell=True)
                gateway_match = re.search(r'via (\d+\.\d+\.\d+\.\d+)', result.stdout)
                if gateway_match:
                    return gateway_match.group(1)
            return "No disponible"
        except:
            return "No disponible"
    
    def is_valid_device(self, ip, mac):
        """Filtra dispositivos válidos."""
        try:
            if ipaddress.IPv4Address(ip).is_multicast:
                return False
            if ip.endswith('.0') or ip.endswith('.255'):
                return False
            if not ip.startswith(self.local_ip.rsplit('.', 1)[0] + '.'):
                return False
            if mac and (mac.startswith('01:00:5e') or mac.startswith('01-00-5e') or 
                       mac.startswith('33:33:') or mac.startswith('33-33-')):
                return False
            if mac and (mac.startswith('00:50:56') or mac.startswith('00-50-56') or
                       mac.startswith('00:0c:29') or mac.startswith('00-0c-29') or
                       mac.startswith('00:15:5d') or mac.startswith('00-15-5d')):
                return False
            return True
        except:
            return False
    
    def arp_scan(self):
        """Escaneo usando tabla ARP filtrado."""
        devices = []
        try:
            system = platform.system().lower()
            
            if system == "windows":
                result = subprocess.run("arp -a", capture_output=True, text=True, shell=True)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})', line)
                    
                    if ip_match and mac_match:
                        ip = ip_match.group(1)
                        mac = mac_match.group(0)
                        
                        if self.is_valid_device(ip, mac):
                            vendor = self.mac_vendor_lookup.get_vendor(mac)
                            
                            devices.append({
                                'ip': ip,
                                'mac': mac.replace('-', ':'),
                                'vendor': vendor,
                                'type': 'Local' if ip == self.local_ip else 'Remoto',
                                'method': 'ARP'
                            })
            
            else:  # Linux/macOS
                result = subprocess.run("arp -n", capture_output=True, text=True, shell=True)
                lines = result.stdout.split('\n')
                
                for line in lines:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    mac_match = re.search(r'([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})', line)
                    
                    if ip_match and mac_match:
                        ip = ip_match.group(1)
                        mac = mac_match.group(0)
                        
                        if self.is_valid_device(ip, mac):
                            vendor = self.mac_vendor_lookup.get_vendor(mac)
                            
                            devices.append({
                                'ip': ip,
                                'mac': mac,
                                'vendor': vendor,
                                'type': 'Local' if ip == self.local_ip else 'Remoto',
                                'method': 'ARP'
                            })
            
            return devices
            
        except Exception as e:
            print(f"Error en escaneo ARP: {e}")
            return []
    
    def ping_scan(self, timeout=3):
        """Escaneo por ping de la red local."""
        devices = []
        network = ipaddress.IPv4Network(self.network, strict=False)
        
        def ping_ip(ip_str):
            try:
                system = platform.system().lower()
                param = "-n 1 -w 1000" if system == "windows" else "-c 1 -W 1"
                command = f"ping {param} {ip_str} >nul 2>&1" if system == "windows" else f"ping {param} {ip_str} >/dev/null 2>&1"
                
                if os.system(command) == 0:
                    mac = self.get_mac_from_arp(ip_str)
                    if mac != "No encontrada" and self.is_valid_device(ip_str, mac):
                        vendor = self.mac_vendor_lookup.get_vendor(mac)
                        devices.append({
                            'ip': ip_str,
                            'mac': mac,
                            'vendor': vendor,
                            'type': 'Local' if ip_str == self.local_ip else 'Remoto',
                            'method': 'PING'
                        })
            except:
                pass
        
        threads = []
        print("🔄 Escaneando por ping...")
        
        for ip in network.hosts():
            ip_str = str(ip)
            
            if ip_str == self.local_ip:
                continue
                
            if not self.is_valid_device(ip_str, None):
                continue
                
            thread = threading.Thread(target=ping_ip, args=(ip_str,))
            threads.append(thread)
            thread.start()
            
            if len(threads) >= 20:
                for t in threads:
                    t.join(timeout=1)
                threads = []
        
        for t in threads:
            t.join(timeout=1)
            
        return devices
    
    def get_mac_from_arp(self, ip):
        """Obtiene MAC de una IP específica usando ARP."""
        try:
            system = platform.system().lower()
            
            if system == "windows":
                result = subprocess.run(f"arp -a {ip}", capture_output=True, text=True, shell=True)
                mac_match = re.search(r'([0-9A-Fa-f]{2}[-]){5}([0-9A-Fa-f]{2})', result.stdout)
                if mac_match:
                    return mac_match.group(0).replace('-', ':')
            else:
                result = subprocess.run(f"arp -n {ip}", capture_output=True, text=True, shell=True)
                mac_match = re.search(r'([0-9A-Fa-f]{2}[:]){5}([0-9A-Fa-f]{2})', result.stdout)
                if mac_match:
                    return mac_match.group(0)
            
            return "No encontrada"
        except:
            return "No encontrada"
    
    def comprehensive_scan(self):
        """Escaneo completo combinando métodos."""
        print("🔍 Iniciando escaneo completo de red...")
        print("⏳ Esto puede tomar unos segundos...\n")
        
        # Agregar nuestro propio dispositivo primero
        local_mac = self.get_local_mac_address()
        devices = [{
            'ip': self.local_ip,
            'mac': local_mac,
            'vendor': self.mac_vendor_lookup.get_vendor(local_mac),
            'type': 'Local',
            'method': 'Sistema'
        }]
        
        # Escaneo ARP
        arp_devices = self.arp_scan()
        
        # Escaneo PING
        ping_devices = self.ping_scan()
        
        # Combinar resultados evitando duplicados
        all_ips = {device['ip'] for device in devices}
        
        for device in arp_devices + ping_devices:
            if device['ip'] not in all_ips:
                devices.append(device)
                all_ips.add(device['ip'])
        
        return devices

def main():
    scanner = AdvancedNetworkScanner()
    
    print("🛰️  ESCÁNER DE RED MEJORADO - DETECCIÓN AVANZADA")
    print("=" * 60)
    
    # Mostrar información del sistema
    system_info = scanner.get_system_info()
    print("\n📊 INFORMACIÓN DE TU DISPOSITIVO:")
    print("-" * 40)
    for key, value in system_info.items():
        print(f"{key.replace('_', ' ').title():<20}: {value}")
    
    # Escanear red
    print(f"\n🔍 Escaneando red: {scanner.network}")
    print("📡 Consultando fabricantes...")
    devices = scanner.comprehensive_scan()
    
    # Ordenar dispositivos por IP
    devices.sort(key=lambda x: [int(octeto) for octeto in x['ip'].split('.')])
    
    print(f"\n📱 DISPOSITIVOS EN LA RED LOCAL ({len(devices)}):")
    print("=" * 85)
    print(f"{'IP':<15} {'MAC':<18} {'TIPO':<8} {'MÉTODO':<8} {'FABRICANTE':<30}")
    print("-" * 85)
    
    for device in devices:
        print(f"{device['ip']:<15} {device['mac']:<18} {device['type']:<8} {device['method']:<8} {device['vendor']:<30}")
    
    print(f"\n✅ Escaneo completado: {len(devices)} dispositivos encontrados")
    print(f"🕐 Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Análisis mejorado
    if len(devices) > 1:
        print(f"\n🔍 ANÁLISIS DETALLADO:")
        
        # Encontrar dispositivo local
        local_device = next((d for d in devices if d['type'] == 'Local'), None)
        if local_device:
            print(f"   - Tu PC: {local_device['ip']} ({local_device['vendor']})")
        
        # Encontrar router
        router_device = next((d for d in devices if d['ip'] == system_info['gateway']), None)
        if router_device:
            print(f"   - Router: {router_device['ip']} ({router_device['vendor']})")
        
        # Encontrar otros dispositivos
        other_devices = [d for d in devices if d['type'] == 'Remoto' and d['ip'] != system_info['gateway']]
        if other_devices:
            print(f"   - Otros dispositivos ({len(other_devices)}):")
            for device in other_devices:
                print(f"     • {device['ip']} - {device['vendor']}")

if __name__ == "__main__":
    if platform.system().lower() == "windows":
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("⚠️  Ejecuta como administrador para mejores resultados")
        except:
            pass
    
    try:
        import requests
    except ImportError:
        print("❌ La biblioteca 'requests' no está instalada.")
        print("💡 Instálala con: pip install requests")
        exit(1)
    
    main()
