import os

def main():
    try:
        import nmap
        import socket
        from cryptography.fernet import Fernet
        from reportlab.pdfgen import  canvas
        from twilio.rest import Client
    except ImportError:
        os.system('pip install python-nmap')
        os.system('pip install cryptography')
        os.system('pip install sockets')
        os.system('pip install reportlab')
        os.system('pip install twilio')
        print('Instalando liberias ...')
    

if __name__ == "__main__":
    main()