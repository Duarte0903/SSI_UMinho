import asyncio
import base64
import os
import traceback
import valida_cert as valida
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

conn_port = 8443
max_msg_size = 9999

p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
g = 2
parameters_numbers = dh.DHParameterNumbers(p, g)
parameters = parameters_numbers.parameters(default_backend())

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
        self.server_dh_public_key = None

        self.pseudonym = None

        self.dh_private_key = None
        self.dh_public_key = None

        self.shared_key = None
        self.derived_key = None

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

            self.pseudonym = user_cert.subject.get_attributes_for_oid(x509.NameOID.PSEUDONYM)[0].value

            self.public_key = self.private_key.public_key()
            print("User public key loaded!")

            self.dh_private_key = parameters.generate_private_key()
            self.dh_public_key = self.dh_private_key.public_key()
            print("DH keys generated!")

            user_dh_pub_key_bytes = self.dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

            send_pair = mkpair(self.pseudonym.encode(), user_dh_pub_key_bytes)
            send_pair_b64 = base64.b64encode(send_pair)

            send_msg = b"user_pub_key " + send_pair_b64

            return send_msg
        
        elif cmd == "server_key":
            if isinstance(msg, str):
                msg = msg.encode()

            server_key_data_b64 = msg.split(b' ')[1]
            full_pair = base64.b64decode(server_key_data_b64)

            server_dh_public_key_bytes, sig_cert_pair = unpair(full_pair)

            signature, server_cert_bytes = unpair(sig_cert_pair)

            self.server_cert = x509.load_pem_x509_certificate(server_cert_bytes, default_backend())

            self.server_public_key = self.server_cert.public_key()

            server_dh_public_key = serialization.load_pem_public_key(server_dh_public_key_bytes, default_backend())

            try:
                # Validação do certificado do servidor
                valida.valida_cert(self.server_cert, self.ca_cert)

                user_dh_pub_key_bytes = self.dh_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

                pub_server_user_pair = mkpair(server_dh_public_key_bytes, user_dh_pub_key_bytes)

                user_cert_bytes = self.user_cert.public_bytes(encoding=serialization.Encoding.PEM)

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

                print("Server certificate and signature validated!")

                try:
                    self.shared_key = self.dh_private_key.exchange(server_dh_public_key)
                    print("Shared key generated!")

                    self.derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data',
                    ).derive(self.shared_key)

                except Exception as e:
                    print(e)
                    traceback.print_exc()
                    return "MSG RELAY SERVICE: error generating shared key!"

                self.server_dh_public_key = server_dh_public_key

                pub_user_server_pair = mkpair(user_dh_pub_key_bytes, server_dh_public_key_bytes)

                signature = self.private_key.sign(
                    pub_user_server_pair,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                user_sig_pair = mkpair(signature, user_cert_bytes)

                user_sig_pair_b64 = base64.b64encode(user_sig_pair)

                send_msg = b"user_cert " + user_sig_pair_b64

                return send_msg

            except Exception as e:
                print(e)
                traceback.print_exc()
                return "MSG RELAY SERVICE: error validating server certificate or signature!"

        elif cmd == "send":
            if len(args) != 2:
                return "help"
            
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()

            uid = args[0].encode()
            subject = args[1].encode()

            # verificar se a mensagem excede o limite de 1000 bytes
            while True:
                message = input("Escreve a mensagem (limite de 1000 bytes): ").encode()
                if len(message) <= 1000:
                    break
                print("A mensagem excede o limite de 1000 bytes!")

            cipher = Cipher(algorithms.AES(self.derived_key), modes.CTR(b'\0' * 16), default_backend())
            encryptor = cipher.encryptor()
            encrypted_message = encryptor.update(message) + encryptor.finalize()

            signature = self.private_key.sign(
                encrypted_message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            encrypted_message_pair = mkpair(encrypted_message, signature)

            sub_message_pair = mkpair(subject, encrypted_message_pair)

            uid_sender_pair = mkpair(uid, self.pseudonym.encode())
            send_pair = mkpair(uid_sender_pair, sub_message_pair)

            send_pair_b64 = base64.b64encode(send_pair)

            send_msg = b"send " + send_pair_b64
            return send_msg
        
        elif cmd == "askqueue":
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()
            
            user = self.pseudonym.encode()
            
            signature = self.private_key.sign(
                user,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            user_sign_pair = mkpair(user, signature)
            user_sign_pair_b64 = base64.b64encode(user_sign_pair)

            send_msg = b"askqueue " + user_sign_pair_b64

            return send_msg
            
        elif cmd == "getmsg":
            if len(args) != 1:
                return "help"
            
            if not self.private_key:
                send_msg = "MSG RELAY SERVICE: User data not loaded!"
                return send_msg.encode()
            
            msg_num = args[0].encode()

            user = self.pseudonym.encode()

            signature = self.private_key.sign(
                msg_num,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            signed_msg_num = mkpair(msg_num, signature)

            user_num_sign = mkpair(user, signed_msg_num)

            user_num_sign_b64 = base64.b64encode(user_num_sign)

            send_msg = b"getmsg " + user_num_sign_b64

            return send_msg
        
        elif cmd == "user_queue":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            encrypted_message = base64.b64decode(message_data_b64)

            try:
                cipher = Cipher(algorithms.AES(self.derived_key), modes.CTR(b'\0' * 16), default_backend())
                decryptor = cipher.decryptor()
                message = decryptor.update(encrypted_message) + decryptor.finalize()

                print("Message received: ", message.decode())

            except Exception as e:
                print(e)
                print("Error decrypting message!")
                return "MSG RELAY SERVICE: error decrypting message!"

        elif cmd == "msg":
            if isinstance(msg, str):
                msg = msg.encode()

            message_data_b64 = msg.split(b' ')[1]
            encrypted_message = base64.b64decode(message_data_b64)
            
            try:
                cipher = Cipher(algorithms.AES(self.derived_key), modes.CTR(b'\0' * 16), default_backend())
                decryptor = cipher.decryptor()
                message = decryptor.update(encrypted_message) + decryptor.finalize()

                print("Message received: ", message.decode())

            except Exception as e:
                print("Error decrypting message!")
                return "MSG RELAY SERVICE: error decrypting message!"
        
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