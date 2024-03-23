# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import socket
import sys
import re
import os
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend

conn_port = 8443
max_msg_size = 9999
    
def user_cmd(user, FNAME):
    if FNAME:
        path_name = FNAME
    
    else:
        path_name = "projCA/" + user + ".p12"

    if not os.path.exists(path_name):
        return "ERRO: userdata.p112 não existe"
    
    with open(path_name, "rb") as f:
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

    def process(self, msg=b""):
        self.msg_cnt +=1

        cmd_parts = msg.decode().split(' ')
        cmd = cmd_parts[0]
        args = cmd_parts[1:]
        
        if re.match(r'-(\w+)', cmd):
            user = cmd[1:]
            fname = args

            private_key, user_cert, ca_cert = user_cmd(user, fname)
            self.private_key = private_key
            self.user_cert = user_cert
            self.ca_cert = ca_cert

            return (b"Command processed.", b"")
        
        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        #
        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)

    try:
        while True:
            cmd = input("Comando: ")
            if not cmd:
                continue

            writer.write(cmd.encode())
            await writer.drain()

            response = await reader.read(max_msg_size)
            print(response.decode())

    except asyncio.CancelledError:
        print("Connection closed.")

    writer.close()

def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())

run_client()