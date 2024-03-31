import asyncio
import datetime
import re
import valida_cert as valida
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
import base64

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

def mkpair(x, y):
    len_x = len(x)
    len_x_bytes = len_x.to_bytes(2, "little")
    return len_x_bytes + x + y

def unpair(xy):
    len_x = int.from_bytes(xy[:2], "little")
    x = xy[2 : len_x + 2]
    y = xy[len_x + 2 :]
    return x, y

class ServerWorker(object):
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.msg_cnt = 0
        self.private_key, self.server_cert, self.ca_cert = get_userdata("projCA/MSG_SERVER.p12")

        self.server_public_key = self.private_key.public_key()

        self.user_public_keys_dict = {}  # dicionário de chaves públicas dos utilizadores (UID -> chave pública)
        self.user_public_keys = []       # lista de chaves públicas dos utilizadores
        self.message_queues = {}         # filas de mensagens dos utilizadores UID -> lista de mensagens (mensagem -> <NUM> <SENDER> <TIMESTAMP> <SUBJECT> <MESSAGE> <STATUS>)

    def process(self, msg):
        """ Processa uma mensagem (`bytestring`) enviada pelo CLIENTE.
            Retorna a mensagem a transmitir como resposta (`None` para
            finalizar ligação) """
        txt = msg.decode().strip()
        print('%d : %r' % (self.id, txt))
        parts = txt.split(' ')
        command = parts[0]

        if command == "send":
            # Solução à trolha mas tem que ser assim para já
            if len(parts) == 3:
                return txt
            
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)

            uid, sub_message_pair = unpair(message_data)

            subject, signed_message = unpair(sub_message_pair)

            message, signature = unpair(signed_message)

            try:
                for sender_uid, public_key in self.user_public_keys_dict.items():
                    public_key.verify(
                        signature, 
                        message, 
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()), 
                            salt_length=padding.PSS.MAX_LENGTH
                        ), 
                        hashes.SHA256()
                    )

                    print("Signature verified!")

                    stored_message = (sender_uid, datetime.datetime.now(), subject, message, False)

                    if uid not in self.message_queues:
                        self.message_queues[uid] = []
                        self.message_queues[uid].append(stored_message)

                    else:
                        self.message_queues[uid].append(stored_message)

                    print(self.message_queues)
                    
                    return "MSG RELAY SERVICE: message sent and stored!"
                
            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error verifying message signature!"
               
        elif command == "user_pub_key":
            user_public_key_data = msg.split(b" ")[1:]
            user_public_key_data = b" ".join(user_public_key_data)

            try:
                user_public_key = serialization.load_pem_public_key(user_public_key_data, default_backend())

                self.user_public_keys.append(user_public_key)

                user_public_key_bytes = user_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                server_public_key_bytes = self.server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                pub_server_user_pair = mkpair(server_public_key_bytes, user_public_key_bytes)

                signature = self.private_key.sign(
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                server_cert_bytes = self.server_cert.public_bytes(encoding=serialization.Encoding.PEM)

                sig_cert_pair = mkpair(signature, server_cert_bytes)    
                
                send_pair = mkpair(server_public_key_bytes, sig_cert_pair)
                send_pair_b64 = base64.b64encode(send_pair)

                send_msg = b"server_key " + send_pair_b64

                return send_msg
            
            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error loading user public key!"
            
        elif command == "user_cert":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)

            signature, user_cert_bytes = unpair(message_data)

            user_cert = x509.load_pem_x509_certificate(user_cert_bytes, default_backend())

            try:
                # Validação do certificado do utilizador
                valida.valida_cert(user_cert, self.ca_cert)

                for key in self.user_public_keys:
                    user_pub_key_bytes = key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
                    server_public_key_bytes = self.server_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                    pub_user_server_pair = mkpair(user_pub_key_bytes, server_public_key_bytes)

                    # Validação da assinatura do utilizador
                    key.verify(
                        signature,
                        pub_user_server_pair,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256()
                    )

                    # Adicionar chave pública do utilizador ao dicionário de chaves públicas
                    self.user_public_keys_dict[user_cert.subject.get_attributes_for_oid(NameOID.PSEUDONYM)[0].value] = key

                    return "MSG RELAY SERVICE: user certificate and signature validated!"

            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error validating user certificate and signature!"
            
        elif command == "askqueue":
            # Solução à trolha mas tem que ser assim para já
            #if len(parts) == 2:
            #    return txt
            
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            message_data = base64.b64decode(message_data_b64)
            
            user, signed_cmd = unpair(message_data)
            cmd, signature = unpair(signed_cmd)

            print(self.user_public_keys_dict.items())
            # verificar se alguma chave pública de utilizador valida a assinatura
            try:
                for sender_uid, public_key in self.user_public_keys_dict.items():
                    public_key.verify(
                        signature, 
                        cmd, 
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()), 
                            salt_length=padding.PSS.MAX_LENGTH
                        ), 
                        hashes.SHA256()
                    )

                    print("Signature verified!")

                    if user in self.message_queues:
                        return "MSG RELAY SERVICE: " + str(self.message_queues[user])
                    
                    else:
                        return "MSG RELAY SERVICE: no messages to show!"
            
            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error verifying message signature!"

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
        if isinstance(response, str):
            writer.write(response.encode())
        else:
            writer.write(response)
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