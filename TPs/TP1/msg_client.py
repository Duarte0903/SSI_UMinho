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

        self.server_cert = None
        self.server_public_key = None

        self.pseudonym = None

    def process(self, msg=b""):
        self.msg_cnt +=1

        cmd_parts = msg.decode().split(' ')

        cmd = cmd_parts[0]
        args = cmd_parts[1:]

        if cmd == "-user":
            user = args[0]

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

            self.public_key = self.private_key.public_key()

            print("User public key loaded!")

            send_msg = b"user_pub_key " + self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            return send_msg
        
        elif cmd == "server_key":
            if isinstance(msg, str):
                msg = msg.encode()

            server_key_data_b64 = msg.split(b' ')[1]
            full_pair = base64.b64decode(server_key_data_b64)

            server_public_key_bytes, sig_cert_pair = unpair(full_pair)

            signature, server_cert_bytes = unpair(sig_cert_pair)

            self.server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())

            self.server_public_key = serialization.load_pem_public_key(server_public_key_bytes, default_backend())

            try:
                # Validação do certificado do servidor
                valida.valida_cert(self.server_cert, self.ca_cert)

                user_pub_key_bytes = self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                pub_server_user_pair = mkpair(server_public_key_bytes, user_pub_key_bytes)

                # Validação da assinatura do servidor
                self.server_public_key.verify(
                    signature,
                    pub_server_user_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                pub_user_server_pair = mkpair(user_pub_key_bytes, server_public_key_bytes)

                signature = self.private_key.sign(
                    pub_user_server_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                user_cert_bytes = self.user_cert.public_bytes(encoding=serialization.Encoding.PEM)

                user_sig_pair = mkpair(signature, user_cert_bytes)

                user_sig_pair_b64 = base64.b64encode(user_sig_pair)

                send_msg = b"user_cert " + user_sig_pair_b64

                return send_msg

            except Exception as e:
                print(e)
                return "MSG RELAY SERVICE: error validating server certificate or signature!"

        elif cmd == "send":
            if len(args) != 2:
                return "help"
            
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()

            uid = args[0].encode()
            subject = args[1].encode()

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
            
            sub_message_pair = mkpair(subject, signed_message)

            send_pair = mkpair(uid, sub_message_pair)

            send_pair_b64 = base64.b64encode(send_pair)

            send_msg = b"send " + send_pair_b64
            return send_msg
        
        elif cmd == "askqueue":
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()
            
            signature = self.private_key.sign(
                cmd.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            signed_cmd = mkpair(cmd.encode(), signature)
            signed_cmd_64 = base64.b64encode(signed_cmd)

            send_msg = b"askqueue " + signed_cmd_64

            return send_msg
            
        elif cmd == "getmsg":
            if len(args) != 1:
                return "help"
            
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()
        
        print('Received (%d): %r' % (self.msg_cnt , msg.decode()))
        print('Input message to send (empty to finish)')
        new_msg = input().encode()
        
        return new_msg if len(new_msg)>0 else None

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    addr = writer.get_extra_info('peername')
    client = Client(addr)
    msg = client.process()
    while msg:
        if isinstance(msg, str):
            msg = msg.encode()

        if msg.startswith(b'-user'):
            msg = client.process(msg)

        if msg == b'askqueue':
            msg = client.process(msg)

        if msg.startswith(b'getmsg'):
            msg = client.process(msg)

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