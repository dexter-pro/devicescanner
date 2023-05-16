import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from reportlab.pdfgen import  canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from email import encoders
from cryptography.fernet import Fernet
import os;from twilio.rest import Client

# Genera una clave de encriptación
clave = Fernet.generate_key()
# Crea un objeto Fernet con la clave generada
fernet = Fernet(clave)

def send_report(correo):
    """
    Enviar el reporte por correo
    """
    origen = 'PIAciber2023@gmail.com'   #agregar correos
    #hacemos la ppeticion de acceso de conexion a SMTP para poder connectarnos y enviar correos
    conn=smtplib.SMTP('smtp.gmail.com', 587)
    conn.starttls()
    conn.login(origen, desencriptar())#agregar contra correo
    #agregamos los datos de envio
    mensaje= MIMEMultipart()
    mensaje['From']=origen
    mensaje['To']= correo
    mensaje['Subject']='Reporte de seguridad'
    #adjunte el archivo pdf
    nom_pdf= 'Reporte_de_Seguridad.pdf'
    adjuntar= open('Reporte_de_Seguridad.pdf','rb')#se abre con el nombre del archivo y con lectura y binario
    #esto es para adjuntar el archivo el 1arg indica  que es de una aplicacion 
    # #y el  2arg indica que  tipo de contenido en este caso  un binario
    terpdf= MIMEBase('application','octet-stream')
    terpdf.set_payload((adjuntar).read())
    encoders.encode_base64(terpdf)
    terpdf.add_header('Content-Disposition', 'attachment', filename='Reporte_de_Seguridad.pdf')
    mensaje.attach(terpdf)
    conn.sendmail(origen,correo,mensaje.as_string())
    conn.quit()

def cargar_clave():
    """
    Obtiene la clave con la que los archivos van a ser desencriptados
    """
    with open('clave.key', 'rb') as archivo:
        key = archivo.read()
    return key

def desencriptar():
    """ 
    Desencripta valor de archivos
    
    Returns:
        _str_: Password desencriptada
    """
    key=cargar_clave()
    objeto_cifrado=Fernet(key)
    with open('password.txt', 'rb') as archivo:
        contenidoen = archivo.read()
    password_desencriptada=objeto_cifrado.decrypt(contenidoen)
    password=password_desencriptada.decode()
    return password

def tw_sid_des():
    """ 
    Obtiene el identificador encriptado del usuario del API Twilio
    """
    key=cargar_clave()
    objeto_cifrado=Fernet(key)
    with open('tw_sid.txt', 'rb') as archivo:
        contenidoen = archivo.read()
    password_desencriptada=objeto_cifrado.decrypt(contenidoen)
    password=password_desencriptada.decode()
    return password

def tw_auth_des():
    """ 
    Obtiene la llave encriptada del usuario del API Twilio
    """
    key=cargar_clave()
    objeto_cifrado=Fernet(key)
    with open('tw_token.txt', 'rb') as archivo:
        contenidoen = archivo.read()
    password_desencriptada=objeto_cifrado.decrypt(contenidoen)
    password=password_desencriptada.decode()
    return password

def send_report_sms():
    """ 
    Notifica al usuario que el escaneo ha concluido
    """
    client = Client(tw_sid_des(), tw_auth_des())

    message = client.messages.create(
    from_='whatsapp:+14155238886',
    body='El escaneo del equipo ha terminado, revisar el reporte',
    to='whatsapp:+5218114890231'
    )

    print(message.sid)