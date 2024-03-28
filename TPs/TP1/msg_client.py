import asyncio
import base64
import os
import re
import valida_cert as valida
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509

conn_port = 8443
max_msg_size = 9999

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None # p12 não está protegido...
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

# Funções mkpair e unpair fornecidas
def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

class Client:
    def __init__(self, sckt=None):
        self.sckt = sckt
        self.msg_cnt = 0
        self.private_key = None
        self.user_cert = None
        self.ca_cert = None
        self.public_key = None
        self.server_public_key = None
        self.pseudonym = None
        self.cn = None
        self.ou = None


    def process(self, msg=b""):
        self.msg_cnt +=1

        cmd_parts = msg.decode().split(' ')
        cmd = cmd_parts[0]
        args = cmd_parts[1:]

        match = re.match(r'^-user (\w+)$', msg.decode())
        if match:
            user = match.group(1)
            if not user:
                return "User data not found!"
            fname = f"projCA/{user}.p12"
            
            if not args:
                fname = "projCA/" + user + ".p12"
                if not os.path.isfile(fname):
                    return "User data not found!"""

            private_key, user_cert, ca_cert = get_userdata(fname)
            self.private_key = private_key
            self.user_cert = user_cert
            self.ca_cert = ca_cert

            self.pseudonym = user_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            self.ou = user_cert.subject.get_attributes_for_oid(x509.NameOID.ORGANIZATIONAL_UNIT_NAME)[0].value
            self.cn = user_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value

            self.public_key = self.user_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            print("User certificate loaded!")

            send_msg = f"user_cert {self.user_cert.public_bytes(encoding=serialization.Encoding.PEM).decode()}"

            return send_msg.encode()
        
        elif cmd == "server_cert":
            try:
                pattern = r'^server_cert\s+'
                certificate = re.sub(pattern, '', msg.decode(), flags=re.MULTILINE)
                
                server_certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
                    
                if valida.valida_cert(server_certificate, server_certificate.subject):
                    self.server_public_key = server_certificate.public_key()
                    print("Server certificate loaded!")
            
            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error loading user certificate!"


        elif cmd == "send":
            if len(args) != 2:
                return "help"
            
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()

            uid = args[0]
            subject = args[1]

            message = input("Escreve a mensagem (limite de 1000 bytes): ").encode()

            signature = self.private_key.sign(
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            signed_message = mkpair(message, signature)

            print(f'SIGNATURE: {signature}\n')

            send_msg = f"send {uid} {subject} {signed_message}".encode()
            return send_msg
        
        elif cmd == "askqueue":
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()
            
        elif cmd == "getmsg":
            if len(args) != 1:
                return "help"
            
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()
        
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
        await writer.drain()

        if msg == b'User data not loaded!':
            print(msg.decode())
            msg = client.process()

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