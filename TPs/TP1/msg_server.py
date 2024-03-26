import asyncio
import datetime
import os
import re
import time
import valida_cert as valida
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography import x509
from cryptography.x509.extensions import ExtensionOID
from cryptography.x509.oid import NameOID

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

help_str = "Usage:\n-user <FNAME>\tSpecify user data file (default: userdata.p12)\n" \
              "send <UID> <SUBJECT>\tSend a message\n" \
                "askqueue\tRequest unread messages\n" \
                "getmsg <NUM>\tRetrieve a specific message\n" \
                "help\tPrint this help message\n"

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    password = None # p12 não está protegido...
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password)
    return (private_key, user_cert, ca_cert)

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key, self.user_cert, self.ca_cert = get_userdata("projCA/MSG_SERVER.p12")

        self.public_key = self.user_cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.user_public_keys = {}  # Dicionário para armazenar as chaves públicas dos utilizadores UID -> chave
        self.message_queues = {}    # Dicionário para armazenar as filas de mensagens dos utilizadores UID -> lista de mensagens

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        txt = msg.decode().strip()
        print('%d : %r' % (self.id, txt))
        parts = txt.split(' ')
        command = parts[0]

        if command == "send":
            if len(parts) < 3:
                return "MSG RELAY SERVICE: command error!" + "\n" + help_str
            
            uid = parts[1]
            subject = parts[2]
            message = parts[3]
            signature = parts[4]

            if uid not in self.user_public_keys:
                return "MSG RELAY SERVICE: UID unkown!"
            
            public_key = self.user_public_keys[uid]

            if public_key.verify(
                signature,
                message.encode(),
                padding.PKCS1v15(),
                hashes.SHA256()
            ):
                timestamp = time.time()
                self.message_queues[uid].append((self.msg_cnt, subject, message, timestamp))
                print(self.message_queues[uid])

            else:
                return "MSG RELAY SERVICE: Invalid signature!"
        
        elif command.startswith("-"):
            return txt
               
        elif command == "user_cert":
            try:
                pattern = r'^user_cert\s+'
                certificate = re.sub(pattern, '', msg.decode(), flags=re.MULTILINE)
                
                user_certificate = x509.load_pem_x509_certificate(certificate.encode(), default_backend())

                if valida.valida_cert(user_certificate, user_certificate.subject):
                    user_uid = user_certificate.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value
                    self.user_public_keys[user_uid] = user_certificate.public_key()
                    self.message_queues[user_uid] = []
                    send_msg = f"server_cert {self.user_cert.public_bytes(encoding=serialization.Encoding.PEM).decode()}"
                    return send_msg
                
                else:
                    return "MSG RELAY SERVICE: certificate not validated!"
            
            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error loading user certificate!"

        elif command == "help":
            return help_str

        else:
            return "MSG RELAY SERVICE: command error!"
        
        return None

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)
    data = await reader.read(max_msg_size)
    while True:
        if not data: continue
        if data[:1] == b'\n': break
        response = srvwrk.process(data)
        if response:
            writer.write(response.encode())
            await writer.drain()
        data = await reader.read(max_msg_size)
    print("[%d]" % srvwrk.id)
    writer.close()

def run_server():
    loop = asyncio.new_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Servindo em {}'.format(server.sockets[0].getsockname()))
    print('  (pressione ^C para finalizar)\n')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nFinalizado!')

run_server()
