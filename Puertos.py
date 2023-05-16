import nmap
import socket

hostname = socket.gethostname();ip_address = socket.gethostbyname(hostname)

def get_local_ip():
    """
    Obtiene la IP de la maquina local
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('192.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP
 
ip_address = get_local_ip()

def UDP (ports):
    """Realiza un escaneo tipo UDP sobre la IP obtenida

    Args:
        ports (_list_): Lista con los puertos a analizar

    Returns:
        _list_: Lista de puertos analizados, regresa: ['puerto', 'estado']
    """
    ports_list = []
    ports_list.append(["Puerto", "Estado"])
    escaner = nmap.PortScanner()
    escaner.scan(ip_address, arguments="-sU -p " + ports)
    for host in escaner.all_hosts():
        print(f"Escaneando host: ", ip_address)
        for port in escaner[host]['udp']:
            ports_list.append([])
            ports_list[len(ports_list) - 1].append(port)
            ports_list[len(ports_list) - 1].append(escaner[host]['udp'][port]["state"])
            print("Puerto : %s\tEstado : %s" % (port, escaner[host]['udp'][port]["state"]))
    return ports_list
            
def TCP(ports):
    """Realiza un escaneo tipo TCP sobre la IP obtenida

    Args:
        ports (_list_): Lista con los puertos a analizar

    Returns:
        _list_: Lista de puertos analizados, regresa: ['puerto', 'estado']
    """
    ports_list = []
    ports_list.append(["Puerto", "Estado"])
    escaner = nmap.PortScanner()
    escaner.scan(ip_address, arguments="-sS -p " + ports)
    for host in escaner.all_hosts():
        print("Escaneando host: ", ip_address )
        for port in escaner[host]['tcp']:
            ports_list.append([])
            ports_list[len(ports_list) - 1].append(port)
            ports_list[len(ports_list) - 1].append(escaner[host]['tcp'][port]["state"])
            print("Puerto : %s\tEstado : %s" % (port, escaner[host]['tcp'][port]["state"]))
    return ports_list