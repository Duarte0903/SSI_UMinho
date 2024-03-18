import asyncio
import socket
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
import re
from cryptography.hazmat.primitives.serialization import pkcs12

conn_port = 8443
max_msg_size = 9999

comandos = [("user", ["FNAME"]),
            ("send", ["UID", "SUBJECT"]),
            ("askqueue", []),
            ("getmsg", ["NUM"]),
            ("help", [])]

help_string = '''MSG RELAY SERVICE: command error! \n
                 Comandos disponiveis: \n
                 user FNAME - Regista o utilizador com o nome FNAME\n
                 send UID SUBJECT - Envia uma mensagem com o assunto SUBJECT para o utilizador com o identificador UID\n
                 askqueue - Pede a lista de mensagens na fila\n
                 getmsg NUM - Pede a mensagem com o numero NUM\n
                 help - Mostra esta mensagem\n'''

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None # p12 não está protegido...
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

class Client:
    def __init__(self, sckt=None):
        self.user = None
        self.sckt = sckt
        self.msg_cnt = 0
        self.private_key = None
        self.user_cert = None
        self.ca_cert = None

    def process(self, cmd, args):
        self.msg_cnt +=1

        if re.match(r'-(\w+)', cmd):
            if len(args) < 1:
                print("ERRO: argumentos invalidos")

            self.user = cmd[0:]
            
            if len(args) == 1:
                private_key, user_cert, ca_cert = get_userdata(args[0])
                self.private_key = private_key
                self.user_cert = user_cert
                self.ca_cert = ca_cert
 
        elif cmd == "send":
            if len(args) != 2:
                print("ERRO: argumentos invalidos")

            receiver_uid = args[0]
            subject = args[1]

            if len(subject) > 1000:
                print("Tamanho do assunto excede o limite")
                return
            
            if not self.user_cert or not self.private_key:
                print("ERRO: Utilizador não autenticado.")
                return
            
            message = f"From: {self.user}\nTo: {receiver_uid}\nSubject: {subject}\nTimestamp: {datetime.datetime.now()}\n"

            signature = self.private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            full_message = f"{message}\nSignature: {signature.hex()}"
            self.sckt.sendall(full_message.encode())
        
        elif cmd == "askqueue":
            if len(args) != 0:
                print("ERRO: argumentos invalidos")

            msg = "askqueue"
            self.sckt.sendall(msg.encode())
            response = self.sckt.recv(max_msg_size).decode()

            if response:
                print('Mensagens na fila:\n')
                messages = response.split('\n')
                for message in messages:
                    print(message)
            else: 
                print('Nao existem mensagens na fila')

        elif cmd == "getmsg":
            if len(args) != 1:
                print("ERRO: argumentos invalidos")

            msg_num = args[0]
            msg = f"getmsg {msg_num}"
            self.sckt.sendall(msg.encode())  
            response = self.sckt.recv(max_msg_size).decode()
            print(response)
        
        elif cmd == "help":
            if len(args) != 0:
                print("ERRO: argumentos invalidos")
            
            print(help_string)
        
        else: 
            print("MSG RELAY SERVICE: command error!" + '\n' + help_string)

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)

    while True:
        comando = input("Comando: ").split(" ")
        
        cmd = comando[0]
        args = comando[1:]

        if cmd == "":
            break

        client.process(cmd, args)

    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()