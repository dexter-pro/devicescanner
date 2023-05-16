import argparse;import os;import hashlib;import subprocess;import Puertos;import logging;from datetime import datetime;from cryptography.fernet import Fernet;import smtplib;import sendemail as sendemail
from reportlab.pdfgen import  canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

parser = argparse.ArgumentParser(prog="python scanner.py", description="Scanner de procesos, puertos y archivos descargados", epilog="El programa puede tardar algunos minutos dependiento del rendimiento de tu computadora")
parser.add_argument("--mode", dest="mode", help="Modo de escaneo. Ej: p = analizar puertos, t = analizar procesos")
parser.add_argument('--sendemail', dest="email", help="Ingresa el correo al que se enviara reporte sobre el escaneo")
parser.add_argument("--downloads", help="Analizar descargas", action='store_true')
parser.add_argument("--ports", help="Puerto o rango de puertos. Ej: 22,80 | 20-80 | 22")
parser.add_argument("--scantype", help="Seleccionar el tipo de escaneo TCP/UDP")
parser.add_argument("--sms", help="Enviar notificacion por SMS", action='store_true')

params = parser.parse_args()

def main():
    # Crear listas para mandar a reporte
    processes_list = [];ports_list = [];downloadshash_list = []
    if params.mode == None:print('Debes seleccionar un modo de escaneo, consulte python scanner.py -h');exit() 
    if params.mode != None and "p" in params.mode and params.scantype == None:print('Debe selecionar el tipo de scaneo: ex. --scantype [tcp, udp]');exit()
    if params.downloads == True:
        downloadshash_list = hash_downloads()
    if params.mode != None and "t" in params.mode:
        processes_list = process_analysis()
    if params.mode != None and "p" in params.mode:
        ports_list = ports_analysis()
    if params.email != None:
        send_email(params.email)
    if params.sms == True:
        send_sms()

    #Crea reporte
    create_pdf(processes_list, ports_list, downloadshash_list)
    
    print('Escaneo finalizado, comprobar el reporte')

def hash_downloads():
    """Analiza los valores hash de cada archivo localizado en la carpeta de descargas

    Returns:
        _list_: Lista con ['Archivo', 'Valor Hash']
    """
    hash_down = []
    hash_down.append(['Archivo', 'Hash'])
    try:
        downloads_folder = os.path.expanduser("~/Downloads")  # Ruta de la carpeta de descargas
        for filename in os.listdir(downloads_folder):
            filepath = os.path.join(downloads_folder, filename)
            if os.path.isfile(filepath):
                hash_down.append([])
                with open(filepath, "rb") as f:
                    bytes = f.read()  # Lee el archivo en modo binario
                    hash = hashlib.sha256(bytes).hexdigest()  # Calcula el hash SHA-256
                hash_down[len(hash_down) - 1].append(filename)
                hash_down[len(hash_down) - 1].append(hash)
            print(f"Analizando: {filename}")
        register_log('Se analizo los archivos de /Descargas')
        return hash_down
    except Exception as Argument:
        f = open("logs", "a")
        f.write(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " Error: " + str(Argument) + "\n")
        f.close()

def process_analysis():
    """Analiza los procesos corriendo actualmente

    Returns:
        _list_: Lista con ['ID', 'Nombre proceso', 'Ubicacion del proceso']
    """
    try:
        # Obetener la lista de ID de los procesos corriendo
        id_processes = subprocess.run(["powershell", "Get-Process | Select-Object Id, name"], capture_output=True, text=True)
        processes_list = [];process_log = []
        process_log.append(["ID", "Nombre de proceso","Ubicacion"])

        #Dejar en primera posicion el id, y en segunda el nombre del archivo
        for j in range((len(id_processes.stdout.split()))//2):
            processes_list.append([])
            processes_list[j].append(id_processes.stdout.split()[j*2])
            processes_list[j].append(id_processes.stdout.split()[j*2+1])

        # Busca de acuerdo a la lista anterior cada proceso para obtener su ruta
        for i in range(2, (len(id_processes.stdout.split()))//2):
            print(f"La ruta del proceso {processes_list[i][1]} con id: {processes_list[i][0]} es: {subprocess.run(['powershell', f'(Get-Process -Id {processes_list[i][0]}).path'], capture_output=True, text=True).stdout}" if subprocess.run(['powershell', f'(Get-Process -Id {processes_list[i][0]}).path'], capture_output=True, text=True).stdout != "" else f"La ruta del proceso {processes_list[i][1]} con id: {processes_list[i][0]} no fue encontrada")
            # agregamos la ubicacion de cada proceso ejecutandose
            processes_list[i].append(subprocess.run(['powershell', f'(Get-Process -Id {processes_list[i][0]}).path'], capture_output=True, text=True).stdout)
            if not subprocess.run(['powershell', f'(Get-Process -Id {processes_list[i][0]}).path'], capture_output=True, text=True).stdout == "":
                pass
        process_log = processes_list[2:]
        process_log.insert(0, ["ID", "Nombre de proceso","Ubicacion"])
                
        # Elimina los items que tengan ruta vacia
        j = 0
        while j < len(process_log) - 1:
            while process_log[j][2] == "" and j < len(process_log) - 1:
                process_log.pop(j)
            j += 1
        
        register_log('Obtuvo ubicacion de los procesos ejecutados')
        return process_log
    except Exception as Argument:
        f = open("logs", "a")
        f.write(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " Error: " + str(Argument) + "\n")
        f.close()

def ports_analysis():
    """Verifica que los puertos se encuentren en el estado predeterminado

    Returns:
        _list_: Lista con ['Puerto', 'Estado']
    """
    try:
        ports_list = []
        if params.scantype == "tcp":
            if params.ports == None:
                params.ports = "22,25,80,443,143,110,3389,3306,8080"
            print(f"Ejecutando escaneo TCP sobre los puertos: {params.ports}")
            ports_list = Puertos.TCP(params.ports)
        elif params.scantype == "udp":
            if params.ports == None:
                params.ports = "59,67,68,123,161,389,443,514"
            print(f"Ejecutando escaneo UDP sobre los puertos: {params.ports}")
            ports_list = Puertos.UDP(params.ports)
        register_log('Verificacion de puertos')
        return ports_list
    except Exception as Argument:
        f = open("logs", "a")
        f.write(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " Error: " + str(Argument) + "\n")
        f.close()
    
def send_sms():
    """
    Enviar un mensaje por WhatsApp notificando que se ha concluido el escaneo
    """
    sendemail.send_report_sms()

def register_log(msg):
    """
    Registra las acciones realizadas
    """
    f = open("registros", "a")
    f.write(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " " + str(msg) + "\n")
    f.close()

def create_pdf(processes_list, ports_list, downloadshash_list):
    """
    Esta funcion se encarga de crear un pdf
    """
    try:
        elementos = []
        pdf=SimpleDocTemplate('Reporte_de_seguridad.pdf',pagesize=letter)
        estilo = TableStyle([
            ('BACKGROUND', (0,0), (-1, 0), colors.skyblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Courier-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        data = [[f"Reporte generado por herramienta el dia {str(datetime.now().strftime('%d/%m/%Y'))}"]]
        intro = Table(data)
        intro.setStyle(estilo)
        elementos.append(intro)

        #Lista de procesos
        if not len(processes_list) == 0:
            tabla = Table(processes_list)
            tabla.setStyle(estilo)
            tabla.spaceBefore = 15
            tabla._argW[1] = 80
            tabla._argW[0] = 10
            elementos.append(tabla)

        # Lista de puertos escaneados
        if not len(ports_list) == 0:
            tabla2=Table(ports_list)
            tabla2.setStyle(estilo)
            tabla2.spaceBefore=50
            tabla2._argW[1] = 200
            elementos.append(tabla2)

        # Lista de descargas con valor hash
        if not len(downloadshash_list) == 0:
            tabla3=Table(downloadshash_list)
            tabla3.setStyle(estilo)
            tabla3._argW[0] = 200
            tabla3.spaceBefore=50
            elementos.append(tabla3)

        pdf.build(elementos)
    except Exception as Argument:
        f = open("logs", "a")
        f.write(str(datetime.now().strftime("%Y/%m/%d %H:%M:%S")) + " Error: " + str(Argument) + "\n")
        f.close()
        
def send_email(correo):
    """Envia correo con el reporte creado
    """
    sendemail.send_report(correo)

if __name__ == '__main__':
    main()