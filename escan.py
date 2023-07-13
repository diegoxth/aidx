import platform
import psutil
import socket
import subprocess
import winreg
import os
import wmi
import nmap
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp



def obtener_informacion_sistema():
    informacion = {}

    # Información del sistema operativo
    informacion['Sistema Operativo'] = platform.system()
    informacion['Versión'] = platform.version()
    informacion['Arquitectura'] = platform.machine()

    # Información del hardware
    informacion['Procesador'] = platform.processor()
    informacion['Memoria Total'] = psutil.virtual_memory().total
    informacion['Memoria Disponible'] = psutil.virtual_memory().available
    informacion['Disco Total'] = psutil.disk_usage('/').total
    informacion['Disco Disponible'] = psutil.disk_usage('/').free

    # Información de red
    informacion['Dirección IP'] = obtener_direccion_ip()
    informacion['Dirección MAC'] = obtener_direccion_mac()

    # Información de procesos en ejecución
    informacion['Procesos en Ejecución'] = [p.name() for p in psutil.process_iter()]

    # Verificación de actualizaciones del sistema operativo
    actualizaciones = obtener_actualizaciones()
    informacion['Actualizaciones disponibles (número)'] = len(actualizaciones)
    informacion['Actualizaciones disponibles (nombres)'] = actualizaciones

    # Obtener el antivirus y su versión
    informacion['Antivirus'] = obtener_antivirus()

    # Escanear la red de la empresa
    dispositivos_empresa = escanear_red_empresa()
    informacion['Dispositivos de la Empresa'] = dispositivos_empresa

    # Escanear vulnerabilidades o puertos
    dispositivos_vulnerables = scan_vulnerabilities(dispositivos_empresa)
    informacion['Dispositivos Vulnerables'] = dispositivos_vulnerables
    
    return informacion


def obtener_direccion_ip():
    # Obtener la dirección IP del equipo
    direccion_ip = socket.gethostbyname(socket.gethostname())
    return direccion_ip


def obtener_direccion_mac():
    interfaces = psutil.net_if_addrs()
    for interfaz in interfaces:
        if interfaz != 'lo':
            for direccion in interfaces[interfaz]:
                if direccion.family == psutil.AF_LINK:
                    return direccion.address

    return "Dirección MAC no encontrada"


def obtener_actualizaciones():
    actualizaciones = []
    c = wmi.WMI()
    for update in c.Win32_QuickFixEngineering():
        if update.HotFixID is not None:
            actualizaciones.append(update.Caption)

    return actualizaciones


def obtener_antivirus():
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender") as key:
            antivirus = winreg.QueryValueEx(key, "DisplayName")[0]
            version = winreg.QueryValueEx(key, "ProductVersion")[0]
            return f"{antivirus} - Versión: {version}"
    except FileNotFoundError:
        return "Antivirus no encontrado"


def escanear_red_empresa():
    direccion_ip = obtener_direccion_ip()
    prefijo_red = obtener_prefijo_red(direccion_ip)

    nm = nmap.PortScanner()
    nm.scan(f"{direccion_ip}/{prefijo_red}", arguments='-p-')

    dispositivos = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            dispositivo = {
                'Dirección IP': host,
                'Puertos Abiertos': obtener_puertos_abiertos(host),
                # Agrega aquí cualquier otra información que desees obtener de cada dispositivo
            }
            dispositivos.append(dispositivo)

    return dispositivos


def obtener_puertos_abiertos(direccion_ip):
    nm = nmap.PortScanner()
    nm.scan(hosts=direccion_ip, arguments='-p-')

    puertos_abiertos = []
    for host in nm.all_hosts():
        if nm[host].state() == 'up':
            for proto in nm[host].all_protocols():
                lport = nm[host][proto].keys()
                for port in lport:
                    puertos_abiertos.append(port)

    return puertos_abiertos


def obtener_prefijo_red(direccion_ip):
    partes_ip = direccion_ip.split('.')
    binario = ''.join([bin(int(part))[2:].zfill(8) for part in partes_ip])
    return len(binario.rstrip('0'))


def scan_vulnerabilities(dispositivos):
    dispositivos_vulnerables = []

    for dispositivo in dispositivos:
        # Aquí va la lógica para escanear vulnerabilidades o puertos del dispositivo
        dispositivos_vulnerables.append(dispositivo)  # Ejemplo: Agregar el dispositivo a la lista de vulnerables

    return dispositivos_vulnerables


def generar_archivo_readme(informacion_sistema):
    ruta_archivo_readme = os.path.join(os.path.expanduser("~"), "Desktop", "files", "readme.txt")

    with open(ruta_archivo_readme, 'a') as archivo_readme:
        archivo_readme.write("\n\n--- Información del equipo infectado ---\n\n")
        for clave, valor in informacion_sistema.items():
            archivo_readme.write(f"{clave}: {valor}\n")

    print("Archivo 'readme.txt' actualizado con éxito.")


def generar_archivo_infectado(informacion_sistema):
    ruta_archivo_infectado = os.path.join(os.path.expanduser("~"), "Desktop", "files", "info_equipo_infectado.txt")

    with open(ruta_archivo_infectado, 'w') as archivo_infectado:
        for clave, valor in informacion_sistema.items():
            archivo_infectado.write(f"{clave}: {valor}\n")

    print("Archivo 'info_equipo_infectado.txt' creado con éxito en la carpeta 'files'.")


if __name__ == '__main__':
    informacion_sistema = obtener_informacion_sistema()

    ruta_carpeta_files = os.path.join(os.path.expanduser("~"), "Desktop", "files")
    if not os.path.exists(ruta_carpeta_files):
        os.makedirs(ruta_carpeta_files)

    generar_archivo_readme(informacion_sistema)
    generar_archivo_infectado(informacion_sistema)
