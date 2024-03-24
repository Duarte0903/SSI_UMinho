# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import sys
import re
import os
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

conn_port = 8443
max_msg_size = 9999

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None # p12 não está protegido...
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

class Client:
    def __init__(self, sckt=None):
        self.sckt = sckt
        self.msg_cnt = 0
        self.private_key = None
        self.user_cert = None
        self.ca_cert = None
        self.public_key = None
        self.server_public_key = None
        self.shared_key = None

    def process(self, msg=b""):
        self.msg_cnt +=1

        cmd_parts = msg.decode().split(' ')
        cmd = cmd_parts[0]
        args = cmd_parts[1:]

        if re.match(r'-(\w+)', msg.decode()):
            user = cmd[1:]

            if not args:
                fname = "projCA/" + user + ".p12"
                if not os.path.isfile(fname):
                    return "User data not found!"
            else:
                fname = args[0]
                if not os.path.isfile(fname):
                    return "User data not found!"

            private_key, user_cert, ca_cert = get_userdata(fname)
            self.private_key = private_key
            self.user_cert = user_cert
            self.ca_cert = ca_cert

            self.public_key = self.user_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            send_msg = f"public {self.public_key.decode()}\n"
            return send_msg.encode()
        
        elif cmd == "server_public":
            server_public_key = args[0].encode()
            self.server_public_key = server_public_key
            
        elif cmd == "send":
            if len(args) != 2:
                return "help"

            uid = args[0]
            subject = ' '.join(args[1:])

            print("Escreva a mensagem (limite de 1000 bytes): ")
            message = input()[:1000]

            signature = self.private_key.sign(
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            return f"send {uid} {subject} {message} {signature}"
        
        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        #
        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()